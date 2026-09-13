/*
 * instr_plan.c - 插桩规划(纯逻辑,无系统调用)
 *
 * 生成两类守卫:
 *   call-guard   :if (check(arg)) { 调用 callee } —— 包裹单条 bl
 *   block-guard  :if (check(arg)) { 代码块 }     —— 包裹任意代码块
 *
 * 补丁两种形态:
 *   A(12 字节):adrp x16, tramp; add x16, x16, #lo12; br x16
 *               要求 tramp 与 guard 页距在 ±4GB 内;搬移 2/3 条指令
 *   B(16 字节):ldr x16, [pc, #8]; br x16; .quad tramp
 *               无距离限制;搬移 3/4 条指令
 *
 * trampoline 完全位置无关:所有绝对地址经内联字面量池加载。
 * 前向分支(cbz / b)在发射结束后统一回填。
 */
#include "instr_internal.h"
#include "a64.h"

#include <string.h>

/* ---------------- 小型发射器 ---------------- */

typedef struct {
    uint32_t *w;
    size_t n;
    size_t cap;
    uint64_t base; /* trampoline 运行时基址(重定位 PC 相对指令用) */
    int err;
} em_t;

static uint64_t em_here(const em_t *e) {
    return e->base + (uint64_t)e->n * 4;
}

static void em_put(em_t *e, uint32_t insn) {
    if (e->err || e->n >= e->cap) {
        e->err = 1;
        return;
    }
    e->w[e->n++] = insn;
}

/*
 * ldr x<reg>, [pc, #8]; b +8; .quad val —— 4 个字,完全位置无关。
 * b 跳过字面量,避免执行流落入数据。
 */
static void em_put_lit(em_t *e, int reg, uint64_t val) {
    uint64_t pc = em_here(e);
    em_put(e, a64_insn_ldr_lit(reg, 1, pc + 8, pc));
    em_put(e, a64_insn_b(pc + 16, pc + 4));
    em_put(e, (uint32_t)(val & 0xFFFFFFFFu));
    em_put(e, (uint32_t)(val >> 32));
}

/* 发射一条被搬移指令(从 old_pc 搬到 trampoline 当前位置) */
static int em_put_displaced(em_t *e, uint64_t old_pc, uint32_t insn) {
    uint32_t out;
    int r = a64_relocate_displaced(old_pc, insn, em_here(e), &out);
    if (r == 0 || r == 1) {
        em_put(e, out);
        return 0;
    }
    a64_insn_t d;
    a64_decode(old_pc, insn, &d);
    switch (d.kind) {
    case A64_BL:
        /* bl 超范围:绝对装载 + 间接调用 */
        em_put_lit(e, 16, d.target);
        em_put(e, a64_insn_blr(16));
        return 0;
    case A64_B:
        /* b 超范围:绝对装载 + 间接跳转 */
        em_put_lit(e, 16, d.target);
        em_put(e, a64_insn_br(16));
        return 0;
    case A64_LDR_LIT:
        /* ldr xN, label 超范围(±1MB):先绝对装载 label 地址,再间接取内存 */
        em_put_lit(e, 16, d.target);
        em_put(e, a64_insn_ldr_imm(d.rt, 16, 0, d.is64));
        return 0;
    case A64_ADRP:
        /* adrp xN, page 超范围(±4GB):绝对装载页地址 */
        em_put_lit(e, 16, d.page);
        em_put(e, a64_insn_mov_reg(d.rd, 16, 1));
        return 0;
    case A64_ADR:
        /* adr xN, target 超范围(±1MB):绝对装载地址 */
        em_put_lit(e, 16, d.target);
        em_put(e, a64_insn_mov_reg(d.rd, 16, 1));
        return 0;
    case A64_B_COND:
        /* b.cond target 超范围(±1MB):条件不满足 → 跳过绝对跳;满足 → 绝对跳 */
        em_put(e, a64_insn_b_cond(em_here(e) + 6 * 4, em_here(e),
                                  (int)(insn & 15) ^ 1));
        em_put_lit(e, 16, d.target);
        em_put(e, a64_insn_br(16));
        return 0;
    case A64_CBZ: {
        int cbnz = ((insn & 0x7E000000) == 0x35000000 ||
                    (insn & 0x7E000000) == 0xB5000000);
        /* cbz rt,target:rt==0 跳。反转:cbnz rt,skip;绝对跳 target;skip: 继续 */
        em_put(e, cbnz ? a64_insn_cbz(d.rt, d.is64, em_here(e) + 6 * 4, em_here(e))
                       : a64_insn_cbnz(d.rt, d.is64, em_here(e) + 6 * 4, em_here(e)));
        em_put_lit(e, 16, d.target);
        em_put(e, a64_insn_br(16));
        return 0;
    }
    case A64_TBZ: {
        int tbnz = ((insn & 0x7E000000) == 0x37000000 ||
                    (insn & 0x7E000000) == 0xB7000000);
        /* tbz/tbnz rt,#bit,target 超范围(±32KB):反转条件跳到 skip(继续执行),
         * 条件满足时落入绝对跳转序列跳 target。
         * 原 tbz(位==0 跳)→ skip 用 tbnz;原 tbnz(位==1 跳)→ skip 用 tbz。 */
        uint32_t skip = a64_insn_tbz(d.rt, (int)d.imm, d.is64,
                                     em_here(e) + 6 * 4, em_here(e));
        if (!tbnz)
            skip ^= 0x01000000u; /* tbz <-> tbnz 互转 */
        em_put(e, skip);
        em_put_lit(e, 16, d.target);
        em_put(e, a64_insn_br(16));
        return 0;
    }
    default:
        return INSTR_ERR_RELOC;
    }
}

/*
 * 被搬移指令重定位后的实际字数,与 em_put_displaced 的发射完全一致:
 *   非 PC 相对 / 可重定位:1 字;
 *   超范围绝对化:B/BL/LDR_LIT/ADRP/ADR = 5 字,B_COND/CBZ/TBZ = 6 字。
 */
static int displaced_word_count(uint64_t old_pc, uint32_t insn, uint64_t new_pc) {
    uint32_t out;
    int r = a64_relocate_displaced(old_pc, insn, new_pc, &out);
    if (r == 0 || r == 1)
        return 1;
    a64_insn_t d;
    a64_decode(old_pc, insn, &d);
    switch (d.kind) {
    case A64_B:
    case A64_BL:
    case A64_LDR_LIT:
    case A64_ADRP:
    case A64_ADR:
        return 5;
    case A64_B_COND:
    case A64_CBZ:
    case A64_TBZ:
        return 6;
    default:
        return 1;
    }
}

/* ---------------- 模块取指 ---------------- */

static uint32_t fetch_module(void *ctx, uint64_t addr) {
    const elf64_module_t *m = (const elf64_module_t *)ctx;
    if (!m->base || addr < (uint64_t)(uintptr_t)m->base)
        return 0;
    ptrdiff_t off = elf64_va_to_offset(m, addr);
    if (off < 0)
        return 0;
    if (m->size && (size_t)off + 4 > m->size)
        return 0;
    const uint8_t *img = m->image ? m->image : m->base;
    uint32_t w;
    memcpy(&w, img + off, 4);
    return w;
}

/* ---------------- 被搬移指令集合 ---------------- */
/*
 * 补丁会覆盖 [guard, guard+plen),被搬移指令为其中 4 字节对齐的指令。
 * 难点:若被搬移指令是分支且目标指向补丁区内部(如循环跳回),需要把
 * 目标重映射到对应被搬移指令在 trampoline 里的新地址。
 * 两阶段:先定尺寸(目标在补丁区内的一律 1 字),再按最终地址发射。
 */
typedef struct {
    uint64_t pc;
    uint32_t insn;
    uint64_t new_addr; /* 在 trampoline 中的新地址 */
} disp_t;

static int plan_displaced(em_t *e, const elf64_module_t *m,
                          const uint32_t *insns, const uint64_t *pcs, int n,
                          uint64_t guard_pc, int plen, instr_plan_t *out) {
    disp_t dlist[4];
    size_t off = e->n; /* 搬移段从当前位置开始,不是 0 */
    out->disp_count = 0;
    for (int i = 0; i < n; i++) {
        dlist[i].pc = pcs[i];
        dlist[i].insn = insns[i];
        dlist[i].new_addr = e->base + off * 4;
        a64_insn_t d;
        a64_decode(pcs[i], insns[i], &d);
        int internal = (d.kind == A64_B || d.kind == A64_BL) &&
                       d.target >= guard_pc && d.target < guard_pc + (uint64_t)plen;
        if (internal) {
            off += 1;
        } else {
            /* 尺寸必须与实际发射(em_put_displaced)完全一致 */
            off += (size_t)displaced_word_count(pcs[i], insns[i],
                                                e->base + off * 4);
        }
    }
    /* 记录 原地址 -> trampoline 新地址 映射(供外部回跳精确重映射) */
    out->disp_count = 0;
    for (int i = 0; i < n && i < 8; i++) {
        out->disp[out->disp_count].old_pc = dlist[i].pc;
        out->disp[out->disp_count].new_addr = dlist[i].new_addr;
        out->disp_count++;
    }
    for (int i = 0; i < n; i++) {
        a64_insn_t d;
        a64_decode(dlist[i].pc, dlist[i].insn, &d);
        int internal = (d.kind == A64_B || d.kind == A64_BL) &&
                       d.target >= guard_pc && d.target < guard_pc + (uint64_t)plen;
        if (internal) {
            uint64_t new_target = 0;
            for (int j = 0; j < n; j++) {
                if (dlist[j].pc == d.target) {
                    new_target = dlist[j].new_addr;
                    break;
                }
            }
            if (!new_target)
                return INSTR_ERR_RELOC;
            if (d.kind == A64_B) {
                em_put(e, a64_insn_b(new_target, em_here(e)));
            } else {
                em_put(e, a64_insn_bl(new_target, em_here(e)));
            }
        } else {
            int r = em_put_displaced(e, dlist[i].pc, dlist[i].insn);
            if (r)
                return r;
        }
    }
    return 0;
}

/*
 * 扫描目标"落在补丁区 [guard, guard+plen)"的分支指令(B/B.cond/CBZ/CBNZ/
 * TBZ/TBNZ),把它们的目标改写到 guard_pc。这些分支可能来自块内其他位置,
 * 也可能是 block 之后的循环回跳,若不处理会跳进被改写的补丁字节 → 崩溃。
 *
 * 注意:扫描范围不能只到 caller_end。巨型函数(如 Player.Update)常被
 * scan_fn_end 在对齐 ZERO 处截断,循环回跳点(可能在 block_end 之后几
 * KB)会漏掉。因此额外扫到 block_end + 64KB(回跳通常不会更远)。
 *
 * 重映射语义:跳进补丁起点 → 执行补丁跳转 → trampoline 重新走 check:
 * pass 则重放块首指令继续(与原始循环语义一致),skip 则跳块尾。
 * guard_pc 与回跳点同函数内,距离恒在 ±1MB 内,单条指令必可编码。
 *
 * 返回值:0 成功。
 */
static int collect_external_fixups(const elf64_module_t *m,
                                   uint64_t caller_start, uint64_t caller_end,
                                   uint64_t block_end,
                                   uint64_t guard_pc, int plen,
                                   instr_plan_t *out) {
    /*
     * 扫描上界:至少覆盖到 block_end 之后 64KB(巨型函数循环回跳可能越过
     * scan_fn_end 的截断点);以模块 size(base+RVA 上界)为硬上限,防止
     * 越界;同时不超 1M 条指令上限,避免扫进后续函数过多。
     */
    uint64_t base_end = (uint64_t)(uintptr_t)m->base;
    if (m->size)
        base_end += m->size;
    uint64_t scan_end = caller_end;
    uint64_t ext = block_end > 0 ? block_end + 0x10000ULL : caller_end;
    if (ext > scan_end)
        scan_end = ext;
    if (base_end > 0 && scan_end > base_end)
        scan_end = base_end;
    {
        uint64_t cap = caller_start + (uint64_t)(1u << 20) * 4;
        if (scan_end > cap)
            scan_end = cap;
    }

    for (uint64_t pc = caller_start; pc + 4 <= scan_end; pc += 4) {
        /* 补丁区本身会被整体改写,跳过 */
        if (pc >= guard_pc && pc < guard_pc + (uint64_t)plen)
            continue;
        uint32_t insn = fetch_module((void *)m, pc);
        a64_insn_t d;
        a64_decode(pc, insn, &d);

        uint64_t target = 0;
        int is_branch = 0;
        switch (d.kind) {
        case A64_B:
        case A64_B_COND:
        case A64_CBZ:
        case A64_TBZ:
            target = d.target;
            is_branch = 1;
            break;
        default:
            break;
        }
        if (!is_branch)
            continue;
        if (target < guard_pc || target >= guard_pc + (uint64_t)plen)
            continue;

        uint32_t new_insn = 0;
        switch (d.kind) {
        case A64_B:
            new_insn = a64_insn_b(guard_pc, pc);
            break;
        case A64_B_COND:
            new_insn = a64_insn_b_cond(guard_pc, pc, (int)(insn & 15));
            break;
        case A64_CBZ: {
            int cbnz = ((insn & 0x7E000000) == 0x35000000 ||
                        (insn & 0x7E000000) == 0xB5000000);
            new_insn = cbnz ? a64_insn_cbnz(d.rt, d.is64, guard_pc, pc)
                            : a64_insn_cbz(d.rt, d.is64, guard_pc, pc);
            break;
        }
        case A64_TBZ: {
            int tbnz = ((insn & 0x7E000000) == 0x37000000 ||
                        (insn & 0x7E000000) == 0xB7000000);
            new_insn = a64_insn_tbz(d.rt, (int)d.imm, d.is64, guard_pc, pc);
            if (tbnz)
                new_insn ^= 0x01000000u;
            break;
        }
        default:
            break;
        }
        if (!new_insn)
            return INSTR_ERR_RELOC; /* 距离超范围,无法单指令重映射 */

        if (out->fix_count >= INSTR_FIX_MAX)
            return INSTR_ERR_RELOC; /* 回跳点过多,不支持 */
        out->fixes[out->fix_count].addr = pc;
        out->fixes[out->fix_count].orig_insn = insn;
        out->fixes[out->fix_count].new_insn = new_insn;
        out->fix_count++;
    }
    return INSTR_OK;
}

/* ---------------- 保存/恢复序列 ---------------- */

/* 压栈 x0-x7, 保存 NZCV 到栈;block_guard 额外压 x30 */
static void emit_saves(em_t *e, int save_x30) {
    em_put(e, a64_insn_stp_pre(0, 1, 31, -16, 1));
    em_put(e, a64_insn_stp_pre(2, 3, 31, -16, 1));
    em_put(e, a64_insn_stp_pre(4, 5, 31, -16, 1));
    em_put(e, a64_insn_stp_pre(6, 7, 31, -16, 1));
    em_put(e, a64_insn_mrs_nzcv(8));
    em_put(e, a64_insn_str_pre(8, 31, -16, 1));
    if (save_x30)
        em_put(e, a64_insn_str_pre(30, 31, -16, 1));
}

/* 恢复 x0-x7 与 NZCV;save_x30 时先恢复 x30(入栈顺序的逆序) */
static void emit_restores(em_t *e, int save_x30) {
    if (save_x30)
        em_put(e, a64_insn_ldp_post(30, 30, 31, 16, 1));
    em_put(e, a64_insn_ldp_post(8, 8, 31, 16, 1));
    em_put(e, a64_insn_msr_nzcv(8));
    em_put(e, a64_insn_ldp_post(6, 7, 31, 16, 1));
    em_put(e, a64_insn_ldp_post(4, 5, 31, 16, 1));
    em_put(e, a64_insn_ldp_post(2, 3, 31, 16, 1));
    em_put(e, a64_insn_ldp_post(0, 1, 31, 16, 1));
}

/* ---------------- 规划主流程 ---------------- */

int instr_plan_guard(const elf64_module_t *m,
                     uint64_t caller_start, uint64_t caller_end,
                     uint64_t guard_pc, int is_call_guard,
                     uint64_t block_end, uint64_t check_addr,
                     uint64_t callee_addr, uint64_t tramp_base,
                     instr_plan_t *out) {
    if (!m || !out)
        return INSTR_ERR_ARG;
    if ((guard_pc & 3) || (caller_start & 3) || (caller_end & 3) ||
        (is_call_guard ? 0 : (block_end & 3)))
        return INSTR_ERR_UNALIGNED;
    if (guard_pc < caller_start || caller_end <= caller_start)
        return INSTR_ERR_RANGE;

    /* 选择补丁形态 A(12B, adrp 可达)或 B(16B, 无限制) */
    uint32_t adrp_ok = a64_insn_adrp(16, tramp_base, guard_pc);
    int plen = adrp_ok ? INSTR_PATCH_LEN : 16;
    uint64_t cont = guard_pc + (uint64_t)plen;

    if (is_call_guard) {
        if (callee_addr == 0)
            return INSTR_ERR_ARG;
    } else {
        if (block_end <= guard_pc || block_end - guard_pc < (uint64_t)plen ||
            block_end > caller_end)
            return INSTR_ERR_RANGE;
    }
    if (cont > caller_end)
        return INSTR_ERR_RANGE;

    /* 1. 参数位置分析(入口 x0~x7,实例方法时 x0=this) */
    a64_loc_t locs[ANALYSIS_NARGS];
    int nfound = 0;
    if (analysis_locate_args(fetch_module, (void *)m, caller_start,
                             caller_end, guard_pc, locs, &nfound) != 0)
        return INSTR_ERR_NOLOC;
    if (nfound == 0)
        return INSTR_ERR_NOLOC;

    memset(out, 0, sizeof(*out));
    out->addr = guard_pc;
    out->is_call_guard = is_call_guard;
    out->block_end = is_call_guard ? 0 : block_end;

    /* 2. 原指令(用于卸载) */
    for (int i = 0; i < plen; i++) {
        uint32_t w = fetch_module((void *)m, guard_pc + (uint64_t)(i & ~3));
        out->orig[i] = (uint8_t)(w >> ((i & 3) * 8));
    }

    /* 3. 生成 trampoline */
    em_t e;
    e.w = out->tramp;
    e.cap = INSTR_TRAMP_MAX;
    e.n = 0;
    e.base = tramp_base;
    e.err = 0;

    /*
     * 3a. 恢复入口参数 x0~x7(未恢复的置 0),与 dobby 的替换函数一致:
     *     实例方法时 x0 = this,x1 = 第一个显式参数,...
     * 注意:sp 槽位必须在压栈之前读取(sp 即将变化)。
     */
    for (int k = 0; k < ANALYSIS_NARGS; k++) {
        if (locs[k].kind == LOC_SLOT && locs[k].base_reg == 31) {
            int64_t off = locs[k].off;
            int sh = locs[k].is64 ? 3 : 2;
            if (off >= 0 && (off & ((1 << sh) - 1)) == 0 &&
                (off >> sh) <= 0xFFF) {
                em_put(&e, a64_insn_ldr_imm(9 + k, 31, off, locs[k].is64));
            } else if (off >= 0 && off <= 4095) {
                em_put(&e, a64_insn_add_imm(9 + k, 31, (uint16_t)off, 1));
                em_put(&e, a64_insn_ldr_imm(9 + k, 9 + k, 0, locs[k].is64));
            } else if (off < 0 && -off <= 4095) {
                em_put(&e, a64_insn_sub_imm(9 + k, 31, (uint16_t)(-off), 1));
                em_put(&e, a64_insn_ldr_imm(9 + k, 9 + k, 0, locs[k].is64));
            } else {
                return INSTR_ERR_NOLOC;
            }
        }
    }

    /* 3b. 保存现场 */
    emit_saves(&e, !is_call_guard);

    /* 3c. 源寄存器落在 x0..x7 的参数先进 staging(x9..x16),避免目标覆盖 */
    for (int k = 0; k < ANALYSIS_NARGS; k++) {
        if (locs[k].kind == LOC_REG && locs[k].reg <= 7 && locs[k].reg != k)
            em_put(&e, a64_insn_mov_reg(9 + k, locs[k].reg, 1));
    }

    /* 3d. 装载到 x0..x7 */
    for (int k = 0; k < ANALYSIS_NARGS; k++) {
        if (locs[k].kind == LOC_REG) {
            if (locs[k].reg == k)
                continue;
            if (locs[k].reg <= 7)
                em_put(&e, a64_insn_mov_reg(k, 9 + k, 1));
            else
                em_put(&e, a64_insn_mov_reg(k, locs[k].reg, 1));
        } else if (locs[k].kind == LOC_SLOT) {
            if (locs[k].base_reg == 31) {
                em_put(&e, a64_insn_mov_reg(k, 9 + k, 1));
            } else { /* x29 槽 */
                int64_t off = locs[k].off;
                int sh = locs[k].is64 ? 3 : 2;
                if (off >= 0 && (off & ((1 << sh) - 1)) == 0 &&
                    (off >> sh) <= 0xFFF) {
                    em_put(&e, a64_insn_ldr_imm(k, 29, off, locs[k].is64));
                } else if (off >= 0 && off <= 4095) {
                    em_put(&e, a64_insn_add_imm(9 + k, 29, (uint16_t)off, 1));
                    em_put(&e, a64_insn_ldr_imm(k, 9 + k, 0, locs[k].is64));
                } else if (off < 0 && -off <= 4095) {
                    em_put(&e, a64_insn_sub_imm(9 + k, 29, (uint16_t)(-off), 1));
                    em_put(&e, a64_insn_ldr_imm(k, 9 + k, 0, locs[k].is64));
                } else {
                    return INSTR_ERR_NOLOC;
                }
            }
        } else {
            em_put(&e, a64_insn_mov_reg(k, 31, 1)); /* mov xk, xzr */
        }
    }

    /* 3e. mycheck(入口参数...) */
    em_put_lit(&e, 17, check_addr);
    em_put(&e, a64_insn_blr(17));
    size_t cbz_off = e.n;
    em_put(&e, 0); /* 占位:cbz w0, skip */

    if (is_call_guard) {
        /* ---- pass 路径 ---- */
        emit_restores(&e, 0);
        em_put_lit(&e, 16, callee_addr);
        em_put(&e, a64_insn_blr(16));        /* 执行原调用 */
        em_put_lit(&e, 30, guard_pc + 4);    /* x30 = 调用返回地址 */
        size_t b_off = e.n;
        em_put(&e, 0);                       /* 占位:b L_after */

        /* ---- skip 路径 ---- */
        size_t skip_off = e.n;
        emit_restores(&e, 0);
        em_put_lit(&e, 30, guard_pc + 4);    /* x30 = 如同调用刚返回 */
        /* L_after 汇合点 */
        size_t after_off = e.n;

        /* 回填 */
        e.w[cbz_off] = a64_insn_cbz(0, 0, e.base + skip_off * 4,
                                    e.base + cbz_off * 4);
        e.w[b_off] = a64_insn_b(e.base + after_off * 4, e.base + b_off * 4);

        /* ---- 公共尾部:被搬移指令 + 跳 cont ---- */
        {
            uint64_t pcs[4];
            uint32_t insns[4];
            int n = 0;
            for (int k = 4; k < plen; k += 4) {
                pcs[n] = guard_pc + (uint64_t)k;
                insns[n] = fetch_module((void *)m, guard_pc + (uint64_t)k);
                n++;
            }
            int r = plan_displaced(&e, m, insns, pcs, n, guard_pc, plen, out);
            if (r)
                return r;
        }
        em_put_lit(&e, 16, cont);
        em_put(&e, a64_insn_br(16));
    } else {
        /* ---- block-guard ---- */
        /* pass 路径:恢复现场 + 搬移块首指令 + 跳 cont */
        emit_restores(&e, 1);
        size_t pass_off = e.n;
        {
            uint64_t pcs[4];
            uint32_t insns[4];
            int n = 0;
            for (int k = 0; k < plen; k += 4) {
                pcs[n] = guard_pc + (uint64_t)k;
                insns[n] = fetch_module((void *)m, guard_pc + (uint64_t)k);
                n++;
            }
            int r = plan_displaced(&e, m, insns, pcs, n, guard_pc, plen, out);
            if (r)
                return r;
        }
        em_put_lit(&e, 16, cont);
        em_put(&e, a64_insn_br(16));

        /* skip 路径:恢复现场 + 跳块尾 */
        size_t skip_off = e.n;
        emit_restores(&e, 1);
        em_put_lit(&e, 16, block_end);
        em_put(&e, a64_insn_br(16));

        /* 回填 cbz */
        e.w[cbz_off] = a64_insn_cbz(0, 0, e.base + skip_off * 4,
                                    e.base + cbz_off * 4);
        (void)pass_off;
    }

    if (e.err)
        return INSTR_ERR_OTHER;
    out->tramp_words = e.n;

    /* 5. block-guard 附加:扫描 caller 内目标落在补丁区的分支,重映射到 guard。
     *    (call-guard 覆盖单条 bl,不涉及代码块,无需处理) */
    out->fix_count = 0;
    if (!is_call_guard) {
        int rc = collect_external_fixups(m, caller_start, caller_end,
                                         block_end, guard_pc, plen, out);
        if (rc != INSTR_OK)
            return rc;
    }

    /* 4. 补丁字节 */
    if (plen == INSTR_PATCH_LEN) {
        /* 形态 A:adrp x16, tramp; add x16, x16, #lo12; br x16 */
        uint32_t p0 = a64_insn_adrp(16, tramp_base, guard_pc);
        uint32_t p1 = a64_insn_add_imm(16, 16, (uint16_t)(tramp_base & 0xFFF),
                                       1);
        uint32_t p2 = a64_insn_br(16);
        memcpy(out->patch + 0, &p0, 4);
        memcpy(out->patch + 4, &p1, 4);
        memcpy(out->patch + 8, &p2, 4);
    } else {
        /* 形态 B:ldr x16, [pc, #8]; br x16; .quad tramp */
        uint32_t p0 = a64_insn_ldr_lit(16, 1, guard_pc + 8, guard_pc);
        uint32_t p1 = a64_insn_br(16);
        memcpy(out->patch + 0, &p0, 4);
        memcpy(out->patch + 4, &p1, 4);
        memcpy(out->patch + 8, &tramp_base, 8);
    }
    out->patch_len = plen;
    return INSTR_OK;
}
