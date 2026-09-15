/*
 * analysis.c - 入口参数存活位置数据流分析
 *
 * 目标:在 caller 函数范围内,确定其**入口 x0~x7 共 8 个参数**中每一个
 * 在守卫点(guard_pc)处的存活位置 —— 可能仍在某个寄存器里,
 * 也可能已被压栈到 [base, #off](base 可以是 sp / x29 / 任意未被改写且
 * 非易失的基寄存器)。
 *
 * 状态:每个寄存器/栈槽保存一个 8 位掩码(bit k = 持有入口第 k 个参数)。
 * 汇合点逐位取交集(AND),单调递减,必然收敛(must 分析:只在**所有**路径
 * 上都成立的位置才会被报告,保证不产生"看似存活实则已失效"的错误位置)。
 *
 * 健全性规则(与 instr_plan.c 的发射器严格对齐):
 *   - 任何对寄存器 r 的写入都会使以 r 为基址的旧槽位失效
 *     (槽位偏移是相对 r 的旧值编码的);
 *   - pre/post-index 写回会把 rn 的槽位按新值重定基(offset - imm),
 *     同时刚写入的数据按 [rn, 0]/[rn, +step] 登记;
 *   - post-index 寻址的有效地址是 [rn, #0](imm 只是增量),pre 才是 [rn, #imm];
 *   - bl/blr 清除 caller-saved x0-x18 与 x30,以及以它们为基址的槽位;
 *   - 字节/半字存取不登记/不传播槽位(部分宽度≠完整参数);
 *   - 发射器只支持基址 ∈ {x0..x7, x18..x30, sp} 的槽位,
 *     x8..x17 是 trampoline 自身暂存区,提取时视为不可恢复(传 0)。
 *
 * 应用场景:普通函数(check 收 argc)、C++ 实例方法(check 收 this=x0、实参=x1..,
 * 与 dobby 的替换函数一致)。
 */
#include "analysis.h"
#include "a64.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define NARGS      8   /* 跟踪入口 x0~x7 */
#define MAX_SLOTS  64
#define MAX_INSNS  (1u << 18) /* 最多 256K 条指令(1MB 代码),避免巨型函数内存爆炸 */
#define MAX_PASSES 512

typedef struct {
    int16_t base;      /* 基址寄存器(31 = sp) */
    int32_t off;       /* 偏移 */
    uint8_t width;     /* 4 或 8 */
    uint8_t used;      /* 槽位是否已登记 */
} slot_t;

typedef struct {
    uint8_t regs[32];          /* regs[r]:位掩码,bit k = 寄存器 r 持有入口参数 k */
    uint8_t slot_masks[MAX_SLOTS]; /* 每个槽位持有的入口参数位掩码 */
} state_t;

typedef struct {
    a64_fetch_fn fetch;
    void *ctx;
    uint64_t start, end;
    slot_t slots[MAX_SLOTS];
    int nslots;
} ctx_t;

static int slot_index(ctx_t *c, int base, int64_t off, int width) {
    for (int i = 0; i < c->nslots; i++) {
        if (c->slots[i].base == base && c->slots[i].off == off)
            return i;
    }
    if (c->nslots >= MAX_SLOTS)
        return -1;
    int i = c->nslots++;
    c->slots[i].base = (int16_t)base;
    c->slots[i].off = (int32_t)off;
    c->slots[i].width = (uint8_t)(width == 8 ? 8 : 4);
    c->slots[i].used = 1;
    return i;
}

static inline uint8_t slot_mask_of(const ctx_t *c, const state_t *in,
                                   int base, int64_t off) {
    for (int i = 0; i < c->nslots; i++) {
        if (c->slots[i].base == base && c->slots[i].off == off)
            return in->slot_masks[i];
    }
    return 0;
}

/* 使以 base 为基址的所有槽位失效(该寄存器被改写,旧偏移不再可信) */
static inline void kill_slots_base(const ctx_t *c, state_t *out, int base) {
    for (int i = 0; i < c->nslots; i++)
        if (c->slots[i].base == base)
            out->slot_masks[i] = 0;
}

/*
 * 寄存器写回重定基:执行"rn = rn + imm"后,原 [rn, #off] 处的数据
 * 现在位于 [rn, #off - imm](相对新值)。旧槽位清空,新偏移槽位保留。
 * 仅 ld/st 的 pre/post 写回与 add/sub sp 使用;其它寄存器算术一律 kill。
 */
static void rebase_slots(ctx_t *c, state_t *out, int base, int64_t imm) {
    uint8_t saved[MAX_SLOTS];
    int idxs[MAX_SLOTS];
    int nb = 0;
    for (int i = 0; i < c->nslots; i++) {
        if (c->slots[i].base == base && out->slot_masks[i]) {
            int j = slot_index(c, base, (int64_t)c->slots[i].off - imm,
                               c->slots[i].width);
            if (j >= 0 && nb < MAX_SLOTS) {
                saved[nb] = out->slot_masks[i];
                idxs[nb] = j;
                nb++;
            }
        }
    }
    kill_slots_base(c, out, base);
    for (int i = 0; i < nb; i++)
        out->slot_masks[idxs[i]] |= saved[i];
}

/* 转移函数:state_in 在地址 pc 处执行 insn 后的输出 */
static void transfer(const ctx_t *c, uint64_t pc, uint32_t insn,
                     const state_t *in, state_t *out) {
    *out = *in;
    a64_insn_t d;
    a64_decode(pc, insn, &d);

    switch (d.kind) {
    case A64_NOP:
    case A64_MSR:
    case A64_RET:
    case A64_BR:
    case A64_B:
    case A64_B_COND:
    case A64_CBZ:
    case A64_TBZ:
        break; /* 不改变寄存器/槽位,控制流由调用方处理 */

    case A64_MOV_REG:
        if (d.rd == 31) {          /* mov sp, xN:sp 值不可静态跟踪 */
            kill_slots_base(c, out, 31);
            break;
        }
        kill_slots_base(c, out, d.rd);
        out->regs[d.rd] = (d.rm >= 0 && d.rm < 31) ? in->regs[d.rm] : 0;
        break;

    case A64_MOV_IMM:
    case A64_ADRP:
    case A64_ADR:
    case A64_MRS:
    case A64_UNKNOWN:
    case A64_OTHER:
        /* 未识别指令按"写 Rd"保守处理(rd = bits[4:0]) */
        if (d.rd >= 0 && d.rd < 31) {
            out->regs[d.rd] = 0;
            kill_slots_base(c, out, d.rd);
        }
        break;

    case A64_LDR_LIT:
        /* ldr xN, label:装载字面量,与参数无关,必须杀掉 rt(旧实现漏杀) */
        if (d.rt >= 0 && d.rt < 31) {
            out->regs[d.rt] = 0;
            kill_slots_base(c, out, d.rt);
        }
        break;

    case A64_ADD_IMM: {
        int is_sub = (insn & 0x40000000) ? 1 : 0;
        if (d.rd == 29 && d.rn == 31) {
            /* add x29, sp, #imm:sp 槽位换算到 x29(sp/x29 此时指向同一内存) */
            for (int i = 0; i < c->nslots; i++) {
                if (c->slots[i].base == 31 && c->slots[i].used &&
                    in->slot_masks[i]) {
                    int j = slot_index((ctx_t *)c, 29,
                                       (int64_t)c->slots[i].off - d.imm,
                                       c->slots[i].width);
                    if (j >= 0)
                        out->slot_masks[j] |= in->slot_masks[i];
                }
            }
            out->regs[29] = 0;
            break;
        }
        if (d.rd == 31) {          /* sp 为目标 */
            if (d.rn == 31) {      /* add/sub sp, sp, #imm:重定基 sp 槽 */
                int64_t delta = is_sub ? -(int64_t)d.imm : (int64_t)d.imm;
                rebase_slots((ctx_t *)c, out, 31, delta);
            } else {               /* add sp, xN, #imm:sp 值未知 */
                kill_slots_base(c, out, 31);
            }
            break;
        }
        if (d.rd == 29) {          /* x29 自身偏移:旧 x29 槽失效 */
            kill_slots_base(c, out, 29);
            out->regs[29] = 0;
            break;
        }
        kill_slots_base(c, out, d.rd);
        if (d.imm == 0)
            out->regs[d.rd] = (d.rn >= 0 && d.rn < 31) ? in->regs[d.rn] : 0;
        else
            out->regs[d.rd] = 0;
        break;
    }

    case A64_BL:
    case A64_BLR: {
        /* 调用:清除 caller-saved(x0-x18)+ LR 及其槽位;
         * 栈槽与 x19-x29 基址槽(callee-saved)保留 */
        for (int r = 0; r <= 18; r++)
            out->regs[r] = 0;
        out->regs[30] = 0;
        for (int i = 0; i < c->nslots; i++) {
            int b = c->slots[i].base;
            if (b <= 18 || b == 30)
                out->slot_masks[i] = 0;
        }
        break;
    }

    case A64_STR_IMM:
    case A64_STP:
    case A64_STUR: {
        /* 有效地址:pre-index = rn+imm;post-index/offset = rn+0 */
        int64_t eff = (d.mem_mode == 1) ? 0 : d.imm;
        int step = d.is64 ? 8 : 4;
        if (d.mem_width >= 4 && d.rt < 31 && in->regs[d.rt]) {
            int j = slot_index((ctx_t *)c, d.rn, eff, d.mem_width);
            if (j >= 0)
                out->slot_masks[j] = in->regs[d.rt];
        }
        if (d.kind == A64_STP && d.mem_width >= 4 && d.rt2 < 31 &&
            in->regs[d.rt2]) {
            int j = slot_index((ctx_t *)c, d.rn, eff + step, d.mem_width);
            if (j >= 0)
                out->slot_masks[j] = in->regs[d.rt2];
        }
        if (d.updates_rn) {
            rebase_slots((ctx_t *)c, out, d.rn, d.imm);
            if (d.rn < 31)
                out->regs[d.rn] = 0;
        }
        break;
    }

    case A64_LDR_IMM:
    case A64_LDP:
    case A64_LDUR: {
        int64_t eff = (d.mem_mode == 1) ? 0 : d.imm;
        int step = d.is64 ? 8 : 4;
        if (d.rt < 31) {
            out->regs[d.rt] =
                (d.mem_width >= 4) ? slot_mask_of(c, in, d.rn, eff) : 0;
            kill_slots_base(c, out, d.rt);
        }
        if (d.kind == A64_LDP && d.rt2 < 31) {
            out->regs[d.rt2] =
                (d.mem_width >= 4) ? slot_mask_of(c, in, d.rn, eff + step) : 0;
            kill_slots_base(c, out, d.rt2);
        }
        if (d.updates_rn) {
            rebase_slots((ctx_t *)c, out, d.rn, d.imm);
            if (d.rn < 31)
                out->regs[d.rn] = 0;
        }
        break;
    }

    case A64_STR_BH:
        /* 部分宽度存储:不登记槽位(只存了一部分),也不修改 rt */
        break;

    case A64_LDR_BH:
        /* 部分宽度加载:结果不是完整参数 */
        if (d.rt < 31) {
            out->regs[d.rt] = 0;
            kill_slots_base(c, out, d.rt);
        }
        break;

    case A64_LDSTR_REG:
        if (d.is_load) {
            if (d.rt < 31) {
                out->regs[d.rt] = 0;
                kill_slots_base(c, out, d.rt);
            }
        }
        /* 寄存器偏移 store:偏移静态未知,不登记槽位,不修改 rt */
        break;
    }
}

/*
 * 分析 [start, end) 内,guard_pc 处(执行前)入口参数 x0~x7 的存活位置。
 * locs 填 8 项(LOC_UNKNOWN 表示不可恢复),*nfound 为可恢复个数。
 * 返回 0 成功;-1 守卫点不可达。
 */
static int locate_args(a64_fetch_fn fetch, void *ctx,
                       uint64_t start, uint64_t end,
                       uint64_t guard_pc, a64_loc_t *locs, int *nfound) {
    if (!fetch || !locs || end <= start || (end - start) % 4 != 0 ||
        guard_pc < start || guard_pc + 4 > end)
        return -1;

    ctx_t c;
    c.fetch = fetch;
    c.ctx = ctx;
    c.start = start;
    c.end = end;
    c.nslots = 0;

    /*
     * 分析窗口裁剪:入口参数在 guard_pc 处的存活只需 [start, guard_pc] 的
     * 数据流,guard 之后的指令不影响结果。裁剪后 n 大幅减小:
     *   巨型函数(如 Player.Update 数十 KB)下仍是紧凑的;
     *   同时 cap 到 MAX_INSNS 防止 calloc 过大(超限时守卫点不可达 → NOLOC)。
     */
    uint64_t eff_end = guard_pc + 4;   /* 只需扫到 guard 点(含) */
    if (eff_end > end)
        eff_end = end;
    int n = (int)((eff_end - start) / 4);
    if (n > MAX_INSNS)
        n = MAX_INSNS;
    if (n <= 0)
        return -1;

    state_t *st = (state_t *)calloc((size_t)n, sizeof(state_t));
    uint8_t *valid = (uint8_t *)calloc((size_t)n, 1);
    if (!st || !valid) {
        free(st);
        free(valid);
        return -1;
    }

    /* 入口状态:x0~x7 分别持有入口参数 0~7 */
    for (int k = 0; k < NARGS; k++)
        st[0].regs[k] = (uint8_t)(1u << k);
    valid[0] = 1;

    /* 全扫描迭代到不动点(Gauss-Seidel,单调递减必收敛) */
    for (int pass = 0; pass < MAX_PASSES; pass++) {
        int changed = 0;
        for (int idx = 0; idx < n; idx++) {
            if (!valid[idx])
                continue;
            uint64_t pc = start + (uint64_t)idx * 4;
            uint32_t insn = fetch(ctx, pc);
            a64_insn_t d;
            a64_decode(pc, insn, &d);

            state_t out;
            transfer(&c, pc, insn, &st[idx], &out);

            uint64_t succs[3];
            int nsucc = 0;
            switch (d.kind) {
            case A64_RET:
            case A64_BR:
                nsucc = 0;
                break;
            case A64_B:
                succs[nsucc++] = d.target;
                break;
            case A64_B_COND:
            case A64_CBZ:
            case A64_TBZ:
                succs[nsucc++] = d.target;
                /* fallthrough */
            default:
                /* BL/BLR 调用返回后继续执行 pc+4 */
                succs[nsucc++] = pc + 4;
                break;
            }

            for (int s = 0; s < nsucc; s++) {
                uint64_t spc = succs[s];
                if (spc < start || spc + 4 > end)
                    continue;
                int si = (int)((spc - start) / 4);
                if (si >= n)
                    continue;
                if (!valid[si]) {
                    st[si] = out;
                    valid[si] = 1;
                    changed = 1;
                } else {
                    int diff = 0;
                    for (int r = 0; r < 31; r++) {
                        uint8_t m = (uint8_t)(st[si].regs[r] & out.regs[r]);
                        if (m != st[si].regs[r]) {
                            st[si].regs[r] = m;
                            diff = 1;
                        }
                    }
                    for (int i = 0; i < c.nslots; i++) {
                        uint8_t m = (uint8_t)(st[si].slot_masks[i] &
                                              out.slot_masks[i]);
                        if (m != st[si].slot_masks[i]) {
                            st[si].slot_masks[i] = m;
                            diff = 1;
                        }
                    }
                    if (diff)
                        changed = 1;
                }
            }
            if (getenv("INSTR_DEBUG")) {
                fprintf(stderr, "  pc=%llx kind=%d rd=%d rn=%d imm=%lld ",
                        (unsigned long long)pc, (int)d.kind, d.rd, d.rn,
                        (long long)d.imm);
                for (int r = 0; r < 8; r++)
                    fprintf(stderr, "r%d=%02x ", r, out.regs[r]);
                fprintf(stderr, "\n");
            }
        }
        if (!changed)
            break;
    }

    int rc = -1;
    int gidx = (int)((guard_pc - start) / 4);
    if (gidx >= 0 && gidx < n && valid[gidx]) {
        state_t s = st[gidx];
        *nfound = 0;
        for (int k = 0; k < NARGS; k++) {
            uint8_t bit = (uint8_t)(1u << k);
            a64_loc_t *loc = &locs[k];
            loc->kind = LOC_UNKNOWN;
            loc->reg = -1;
            loc->base_reg = -1;
            loc->off = 0;
            loc->is64 = 0;
            /* 优先寄存器 */
            for (int r = 0; r < 31; r++) {
                if (s.regs[r] & bit) {
                    loc->kind = LOC_REG;
                    loc->reg = r;
                    break;
                }
            }
            if (loc->kind == LOC_UNKNOWN) {
                for (int i = 0; i < c.nslots; i++) {
                    if (c.slots[i].used && (s.slot_masks[i] & bit)) {
                        int base = c.slots[i].base;
                        /* 发射器只支持这些基址:x8..x17 是 trampoline 暂存区 */
                        int ok = (base == 31) ||
                                 (base >= 0 && base <= 7) ||
                                 (base >= 18 && base <= 30);
                        if (ok) {
                            loc->kind = LOC_SLOT;
                            loc->base_reg = base;
                            loc->off = c.slots[i].off;
                            loc->is64 = (c.slots[i].width == 8);
                            break;
                        }
                    }
                }
            }
            if (loc->kind != LOC_UNKNOWN)
                (*nfound)++;
        }
        rc = 0;
    }

    free(st);
    free(valid);
    return rc;
}

int analysis_locate_args(a64_fetch_fn fetch, void *ctx,
                         uint64_t start, uint64_t end,
                         uint64_t guard_pc, a64_loc_t *locs, int *nfound) {
    return locate_args(fetch, ctx, start, end, guard_pc, locs, nfound);
}

int analysis_locate_first_arg(a64_fetch_fn fetch, void *ctx,
                              uint64_t start, uint64_t end,
                              uint64_t guard_pc, a64_loc_t *out) {
    a64_loc_t locs[NARGS];
    int nfound = 0;
    if (locate_args(fetch, ctx, start, end, guard_pc, locs, &nfound) != 0)
        return -1;
    if (locs[0].kind == LOC_UNKNOWN)
        return -1;
    *out = locs[0];
    return 0;
}

int analysis_find_callsites(a64_fetch_fn fetch, void *ctx,
                            uint64_t start, uint64_t end,
                            uint64_t callee_va, uint64_t *out, int max) {
    if (!fetch || end <= start || (end - start) % 4 != 0)
        return -1;
    int found = 0;
    for (uint64_t pc = start; pc + 4 <= end && (found < max || max <= 0);
         pc += 4) {
        uint32_t insn = fetch(ctx, pc);
        a64_insn_t d;
        a64_decode(pc, insn, &d);
        if (d.kind == A64_BL && d.target == callee_va) {
            if (out && found < max)
                out[found] = pc;
            found++;
        }
    }
    return found;
}
