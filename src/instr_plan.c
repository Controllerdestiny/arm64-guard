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
    if (r == -1) {
        /* b/bl 超范围:绝对装载 + 间接跳转 */
        a64_insn_t d;
        a64_decode(old_pc, insn, &d);
        if (d.kind == A64_BL) {
            em_put_lit(e, 16, d.target);
            em_put(e, a64_insn_blr(16));
            return 0;
        }
        if (d.kind == A64_B) {
            em_put_lit(e, 16, d.target);
            em_put(e, a64_insn_br(16));
            return 0;
        }
    }
    return INSTR_ERR_RELOC;
}

/* ---------------- 模块取指 ---------------- */

static uint32_t fetch_module(void *ctx, uint64_t addr) {
    const elf64_module_t *m = (const elf64_module_t *)ctx;
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
                          uint64_t guard_pc, int plen) {
    disp_t dlist[4];
    size_t off = e->n; /* 搬移段从当前位置开始,不是 0 */
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
            uint32_t out;
            int r = a64_relocate_displaced(pcs[i], insns[i],
                                           e->base + off * 4, &out);
            off += (r == -1) ? 4 : 1;
        }
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
            int r = plan_displaced(&e, m, insns, pcs, n, guard_pc, plen);
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
            int r = plan_displaced(&e, m, insns, pcs, n, guard_pc, plen);
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
