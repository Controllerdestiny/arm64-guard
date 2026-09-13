/*
 * analysis.c - 入口参数存活位置数据流分析
 *
 * 目标:在 caller 函数范围内,确定其**入口 x0~x7 共 8 个参数**中每一个
 * 在守卫点(guard_pc)处的存活位置 —— 可能仍在某个寄存器里,
 * 也可能已被压栈到 [x29/xsp, #off]。
 *
 * 状态:每个寄存器/栈槽保存一个 8 位掩码(bit k = 持有入口第 k 个参数)。
 * 汇合点逐位取交集(AND),单调递减,必然收敛。
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
#define MAX_INSNS  (1u << 20) /* 最多 1M 条指令(4MB 代码),支持很大的函数 */
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

static inline void kill_sp_slots(const ctx_t *c, state_t *out) {
    for (int i = 0; i < c->nslots; i++)
        if (c->slots[i].base == 31)
            out->slot_masks[i] = 0;
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
        break;

    case A64_MOV_REG:
        if (d.rd >= 0 && d.rd < 31)
            out->regs[d.rd] = (d.rm >= 0 && d.rm < 31) ? in->regs[d.rm] : 0;
        break;

    case A64_MOV_IMM:
    case A64_ADRP:
    case A64_ADR:
    case A64_MRS:
    case A64_LDR_LIT:
    case A64_OTHER:
    case A64_UNKNOWN:
        if (d.rd >= 0 && d.rd < 31)
            out->regs[d.rd] = 0;
        break;

    case A64_ADD_IMM: {
        /* add x29, sp, #imm:sp 槽位换算到 x29(sp/x29 此时指向同一内存) */
        if (d.rd == 29 && d.rn == 31) {
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
        if (d.rd == 31 && d.rn == 31) { /* sub sp, sp, #imm 等:sp 槽失效 */
            kill_sp_slots(c, out);
            break;
        }
        if (d.rd == 29 && d.rn == 29) { /* x29 自身偏移:旧 x29 槽失效 */
            for (int i = 0; i < c->nslots; i++)
                if (c->slots[i].base == 29)
                    out->slot_masks[i] = 0;
            out->regs[29] = 0;
            break;
        }
        if (d.rd < 31) {
            if (d.imm == 0 && d.rn < 31)
                out->regs[d.rd] = in->regs[d.rn];
            else
                out->regs[d.rd] = 0;
        }
        break;
    }

    case A64_BL:
    case A64_BLR: {
        /* 调用:清除 caller-saved(x0-x17)+ LR */
        for (int r = 0; r <= 17; r++)
            out->regs[r] = 0;
        out->regs[30] = 0;
        break;
    }

    case A64_STR_IMM:
    case A64_STUR: {
        if (d.rt < 31 && in->regs[d.rt]) {
            int j = slot_index((ctx_t *)c, d.rn, d.imm, d.is64 ? 8 : 4);
            if (j >= 0)
                out->slot_masks[j] = in->regs[d.rt];
        }
        if (d.updates_rn) {
            if (d.rn == 31)
                kill_sp_slots(c, out);
            else if (d.rn < 31)
                out->regs[d.rn] = 0;
        }
        break;
    }

    case A64_STP: {
        int64_t step = d.is64 ? 8 : 4;
        if (d.rt < 31 && in->regs[d.rt]) {
            int j = slot_index((ctx_t *)c, d.rn, d.imm, d.is64 ? 8 : 4);
            if (j >= 0)
                out->slot_masks[j] = in->regs[d.rt];
        }
        if (d.rt2 < 31 && in->regs[d.rt2]) {
            int j = slot_index((ctx_t *)c, d.rn, d.imm + step, d.is64 ? 8 : 4);
            if (j >= 0)
                out->slot_masks[j] = in->regs[d.rt2];
        }
        if (d.updates_rn) {
            if (d.rn == 31)
                kill_sp_slots(c, out);
            else if (d.rn < 31)
                out->regs[d.rn] = 0;
        }
        break;
    }

    case A64_LDR_IMM:
    case A64_LDUR: {
        if (d.rt < 31)
            out->regs[d.rt] = slot_mask_of(c, in, d.rn, d.imm);
        if (d.updates_rn) {
            if (d.rn == 31)
                kill_sp_slots(c, out);
            else if (d.rn < 31)
                out->regs[d.rn] = 0;
        }
        break;
    }

    case A64_LDP: {
        int64_t step = d.is64 ? 8 : 4;
        if (d.rt < 31)
            out->regs[d.rt] = slot_mask_of(c, in, d.rn, d.imm);
        if (d.rt2 < 31)
            out->regs[d.rt2] = slot_mask_of(c, in, d.rn, d.imm + step);
        if (d.updates_rn) {
            if (d.rn == 31)
                kill_sp_slots(c, out);
            else if (d.rn < 31)
                out->regs[d.rn] = 0;
        }
        break;
    }

    case A64_RET:
    case A64_BR:
    case A64_B:
    case A64_B_COND:
    case A64_CBZ:
    case A64_TBZ:
        break; /* 分支不改变寄存器/槽位,控制流由调用方处理 */
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

    int n = (int)((end - start) / 4);
    if (n > MAX_INSNS)
        n = MAX_INSNS;

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
                        loc->kind = LOC_SLOT;
                        loc->base_reg = c.slots[i].base;
                        loc->off = c.slots[i].off;
                        loc->is64 = (c.slots[i].width == 8);
                        break;
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
