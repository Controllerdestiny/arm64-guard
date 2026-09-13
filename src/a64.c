/*
 * a64.c - AArch64 指令 编码 / 解码 / 重定位(小端)
 *
 * 覆盖本插桩引擎所需的指令子集。所有 PC 相对编码都按
 * (目标地址, 指令地址) 计算,与指令实际所在位置无关,便于重定位。
 */
#include "a64.h"

#include <stddef.h>

/* ------------------------- 工具 ------------------------- */

static int64_t sext(uint64_t v, int bits) {
    int64_t s = (int64_t)v;
    int64_t sign = (int64_t)1 << (bits - 1);
    if (s & sign)
        s |= ~((sign << 1) - 1);
    return s;
}

/* ------------------------- 解码 ------------------------- */

void a64_decode(uint64_t pc, uint32_t insn, a64_insn_t *o) {
    o->insn = insn;
    o->pc = pc;
    o->rd = o->rn = o->rm = -1;
    o->rt = o->rt2 = -1;
    o->is64 = 0;
    o->imm = 0;
    o->target = 0;
    o->page = 0;
    o->updates_rn = 0;
    o->is_load = 0;
    o->is_store = 0;

    uint32_t u = insn;
    o->kind = A64_UNKNOWN;

    /* nop / hint(不影响数据流) */
    if (u == 0xD503201F) {
        o->kind = A64_NOP;
        return;
    }

    /* ret / br / blr:1101 0110 1(0000/0011/0011) 11111 000000 11111 Rn */
    if ((u & 0xFFFFFC1F) == 0xD65F0000) { /* ret */
        o->kind = A64_RET;
        o->rn = (int)((u >> 5) & 31);
        return;
    }
    if ((u & 0xFFFFFC1F) == 0xD61F0000) { /* br */
        o->kind = A64_BR;
        o->rn = (int)((u >> 5) & 31);
        return;
    }
    if ((u & 0xFFFFFC1F) == 0xD63F0000) { /* blr */
        o->kind = A64_BLR;
        o->rn = (int)((u >> 5) & 31);
        return;
    }

    /* b / bl:imm26 */
    if ((u & 0xFC000000) == 0x94000000) { /* bl */
        o->kind = A64_BL;
        o->target = pc + (uint64_t)(sext(u & 0x03FFFFFF, 26) * 4);
        o->rn = -1;
        return;
    }
    if ((u & 0xFC000000) == 0x14000000) { /* b */
        o->kind = A64_B;
        o->target = pc + (uint64_t)(sext(u & 0x03FFFFFF, 26) * 4);
        return;
    }

    /* b.cond:imm19 */
    if ((u & 0xFF000010) == 0x54000000) {
        o->kind = A64_B_COND;
        o->target = pc + (uint64_t)(sext((u >> 5) & 0x7FFFF, 19) * 4);
        return;
    }

    /* cbz / cbnz */
    if ((u & 0x7E000000) == 0x34000000 || (u & 0x7E000000) == 0xB4000000) {
        o->kind = A64_CBZ;
        o->is64 = (u & 0x80000000) ? 1 : 0;
        o->rt = (int)(u & 31);
        o->target = pc + (uint64_t)(sext((u >> 5) & 0x7FFFF, 19) * 4);
        return;
    }
    if ((u & 0x7E000000) == 0x35000000 || (u & 0x7E000000) == 0xB5000000) {
        o->kind = A64_CBZ; /* cbnz 也归入 CBZ 类,靠 target 区分由调用方看 insn */
        o->is64 = (u & 0x80000000) ? 1 : 0;
        o->rt = (int)(u & 31);
        o->target = pc + (uint64_t)(sext((u >> 5) & 0x7FFFF, 19) * 4);
        return;
    }

    /* tbz / tbnz */
    if ((u & 0x7E000000) == 0x36000000 || (u & 0x7E000000) == 0xB6000000 ||
        (u & 0x7E000000) == 0x37000000 || (u & 0x7E000000) == 0xB7000000) {
        o->kind = A64_TBZ;
        o->is64 = (u & 0x80000000) ? 1 : 0;
        o->rt = (int)(u & 31);
        int b5 = (int)((u >> 31) & 1);
        int b40 = (int)((u >> 19) & 0x1F);
        o->imm = (b5 << 5) | b40; /* bit 编号 */
        o->target = pc + (uint64_t)(sext((u >> 5) & 0x3FFF, 14) * 4);
        return;
    }

    /* adr / adrp */
    if ((u & 0x1F000000) == 0x10000000) {
        int immlo = (int)((u >> 29) & 3);
        int64_t immhi = sext((u >> 5) & 0x7FFFF, 19);
        int64_t imm = (int64_t)(((uint64_t)immhi << 2) | (uint64_t)immlo);
        o->rd = (int)(u & 31);
        if (u & 0x80000000) {
            o->kind = A64_ADRP;
            o->page = (pc & ~(uint64_t)0xFFF) + (uint64_t)(imm * 4096);
        } else {
            o->kind = A64_ADR;
            o->target = pc + (uint64_t)imm;
        }
        return;
    }

    /* ldr 字面量(w/x/sw) */
    if ((u & 0xFF000000) == 0x18000000 || (u & 0xFF000000) == 0x58000000 ||
        (u & 0xFF000000) == 0x98000000) {
        o->kind = A64_LDR_LIT;
        o->is64 = ((u & 0xC0000000) == 0x40000000) ? 1 : 0;
        o->rt = (int)(u & 31);
        o->target = pc + (uint64_t)(sext((u >> 5) & 0x7FFFF, 19) * 4);
        o->is_load = 1;
        return;
    }

    /* mrs / msr(寄存器) */
    if ((u & 0xFFF00000) == 0xD5300000) {
        o->kind = A64_MRS;
        o->rd = (int)(u & 31);
        return;
    }
    if ((u & 0xFFF00000) == 0xD5100000) {
        o->kind = A64_MSR;
        o->rn = (int)(u & 31);
        return;
    }

    /* mov wD, wM = orr wD, wzr, wM(shift=0, N=0, imm6=0, Rn=31) */
    /* 字段:Rm = bits[20:16], imm6 = bits[15:10], Rn = bits[9:5], Rd = bits[4:0] */
    if (((u & 0x7F000000) == 0x2A000000 || (u & 0x7F000000) == 0xAA000000) &&
        (u & 0x00E00000) == 0 && (u & 0x0000FC00) == 0 &&
        (u & 0x000003E0) == 0x000003E0) {
        o->kind = A64_MOV_REG;
        o->is64 = (u & 0x80000000) ? 1 : 0;
        o->rd = (int)(u & 31);
        o->rm = (int)((u >> 16) & 31);
        return;
    }

    /* movz / movk / movn */
    if ((u & 0x7F800000) == 0x52800000 || (u & 0x7F800000) == 0xD2800000 ||
        (u & 0x7F800000) == 0x72800000 || (u & 0x7F800000) == 0xF2800000 ||
        (u & 0x7F800000) == 0x12800000 || (u & 0x7F800000) == 0x92800000) {
        o->kind = A64_MOV_IMM;
        o->is64 = (u & 0x80000000) ? 1 : 0;
        o->rd = (int)(u & 31);
        o->imm = (u >> 5) & 0xFFFF;
        o->imm |= ((int64_t)((u >> 21) & 3)) << 16; /* hw */
        return;
    }

    /* add/sub 立即数 */
    if ((u & 0xFF800000) == 0x11000000 || (u & 0xFF800000) == 0x91000000 ||
        (u & 0xFF800000) == 0x51000000 || (u & 0xFF800000) == 0xD1000000) {
        o->kind = A64_ADD_IMM;
        o->is64 = (u & 0x80000000) ? 1 : 0;
        o->rd = (int)(u & 31);
        o->rn = (int)((u >> 5) & 31);
        o->imm = (u >> 10) & 0xFFF;
        return;
    }

    /*
     * 立即数存取两族:
     *   imm12 族(bits[25:22] = 0100/0101/0110):
     *     [21:10] imm12(无 mode 位!),str w/x = 0xB9/0xF9,ldr = 0xB9|0x40,
     *     ldrsw = 0xB9800000
     *   imm9 族(bits[25:22] = 0000/0001):
     *     [21:12] imm9,[11:10] mode(00 无缩放 / 01 post / 10 pre)
     *     stur = 0xB8/0xF8,ldur = 0xB8|0x40
     */
    if ((u & 0xFFC00000) == 0xB9000000 || (u & 0xFFC00000) == 0xF9000000) {
        o->kind = A64_STR_IMM;
        o->is64 = (u & 0x80000000) ? 1 : 0;
        o->rt = (int)(u & 31);
        o->rn = (int)((u >> 5) & 31);
        o->imm = ((u >> 10) & 0xFFF) << (o->is64 ? 3 : 2);
        o->is_store = 1;
        return;
    }
    if ((u & 0xFFC00000) == 0xB9400000 || (u & 0xFFC00000) == 0xF9400000) {
        o->kind = A64_LDR_IMM;
        o->is64 = (u & 0x80000000) ? 1 : 0;
        o->rt = (int)(u & 31);
        o->rn = (int)((u >> 5) & 31);
        o->imm = ((u >> 10) & 0xFFF) << (o->is64 ? 3 : 2);
        o->is_load = 1;
        return;
    }
    /* ldrsw(imm12 族):按 64 位读槽位处理 */
    if ((u & 0xFFC00000) == 0xB9800000) {
        o->kind = A64_LDR_IMM;
        o->is64 = 1;
        o->rt = (int)(u & 31);
        o->rn = (int)((u >> 5) & 31);
        o->imm = ((u >> 10) & 0xFFF) << 2;
        o->is_load = 1;
        return;
    }

    /* stur / ldur / pre / post(imm9 族,含 mode 位) */
    if ((u & 0xFFC00000) == 0xB8000000 || (u & 0xFFC00000) == 0xF8000000 ||
        (u & 0xFFC00000) == 0xB8400000 || (u & 0xFFC00000) == 0xF8400000) {
        int is_ldr = ((u & 0xFFC00000) == 0xB8400000 ||
                      (u & 0xFFC00000) == 0xF8400000);
        o->kind = is_ldr ? A64_LDUR : A64_STUR;
        o->is64 = (u & 0x80000000) ? 1 : 0;
        o->rt = (int)(u & 31);
        o->rn = (int)((u >> 5) & 31);
        o->imm = sext((u >> 12) & 0x1FF, 9);
        int mode = (int)((u >> 10) & 3);
        if (mode == 1 || mode == 3) /* post / pre:写回 rn;mode 2 为 unprivileged */
            o->updates_rn = 1;
        if (is_ldr)
            o->is_load = 1;
        else
            o->is_store = 1;
        return;
    }

    /* stp / ldp */
    if ((u & 0x7FC00000) == 0xA9000000 || (u & 0x7FC00000) == 0xA9800000 ||
        (u & 0x7FC00000) == 0xA8800000 || (u & 0x7FC00000) == 0x29000000 ||
        (u & 0x7FC00000) == 0x29800000 || (u & 0x7FC00000) == 0x28800000) {
        o->kind = A64_STP;
        o->is64 = (u & 0x80000000) ? 1 : 0;
        o->rt = (int)(u & 31);
        o->rn = (int)((u >> 5) & 31);
        o->rt2 = (int)((u >> 10) & 31);
        o->imm = sext((u >> 15) & 0x7F, 7) * (o->is64 ? 8 : 4);
        o->updates_rn = ((u & 0x7FC00000) != 0xA9000000 &&
                         (u & 0x7FC00000) != 0x29000000) ? 1 : 0;
        o->is_store = 1;
        return;
    }
    if ((u & 0x7FC00000) == 0xA9400000 || (u & 0x7FC00000) == 0xA9C00000 ||
        (u & 0x7FC00000) == 0xA8C00000 || (u & 0x7FC00000) == 0x29400000 ||
        (u & 0x7FC00000) == 0x29C00000 || (u & 0x7FC00000) == 0x28C00000) {
        o->kind = A64_LDP;
        o->is64 = (u & 0x80000000) ? 1 : 0;
        o->rt = (int)(u & 31);
        o->rn = (int)((u >> 5) & 31);
        o->rt2 = (int)((u >> 10) & 31);
        o->imm = sext((u >> 15) & 0x7F, 7) * (o->is64 ? 8 : 4);
        o->updates_rn = ((u & 0x7FC00000) != 0xA9400000 &&
                         (u & 0x7FC00000) != 0x29400000) ? 1 : 0;
        o->is_load = 1;
        return;
    }

    /* 其它:保守地按"写 Rd"处理 */
    o->kind = A64_OTHER;
    o->rd = (int)(u & 31);
}

/* ------------------------- 编码 ------------------------- */

uint32_t a64_insn_nop(void) {
    return 0xD503201F;
}

uint32_t a64_insn_br(int rn) {
    return 0xD61F0000 | ((uint32_t)(rn & 31) << 5);
}

uint32_t a64_insn_blr(int rn) {
    return 0xD63F0000 | ((uint32_t)(rn & 31) << 5);
}

uint32_t a64_insn_b(uint64_t target, uint64_t pc) {
    int64_t off = ((int64_t)target - (int64_t)pc) >> 2;
    if (off < -(1LL << 25) || off >= (1LL << 25))
        return 0; /* 超出 imm26 范围 */
    return 0x14000000 | ((uint32_t)off & 0x03FFFFFF);
}

uint32_t a64_insn_bl(uint64_t target, uint64_t pc) {
    int64_t off = ((int64_t)target - (int64_t)pc) >> 2;
    if (off < -(1LL << 25) || off >= (1LL << 25))
        return 0;
    return 0x94000000 | ((uint32_t)off & 0x03FFFFFF);
}

uint32_t a64_insn_b_cond(uint64_t target, uint64_t pc, int cond) {
    int64_t off = ((int64_t)target - (int64_t)pc) >> 2;
    if (off < -(1LL << 18) || off >= (1LL << 18))
        return 0;
    return 0x54000000 | ((uint32_t)off & 0x7FFFF) << 5 | (uint32_t)(cond & 15);
}

uint32_t a64_insn_cbz(int rt, int is64, uint64_t target, uint64_t pc) {
    int64_t off = ((int64_t)target - (int64_t)pc) >> 2;
    if (off < -(1LL << 18) || off >= (1LL << 18))
        return 0;
    uint32_t base = is64 ? 0xB4000000 : 0x34000000;
    return base | ((uint32_t)off & 0x7FFFF) << 5 | (uint32_t)(rt & 31);
}

uint32_t a64_insn_cbnz(int rt, int is64, uint64_t target, uint64_t pc) {
    int64_t off = ((int64_t)target - (int64_t)pc) >> 2;
    if (off < -(1LL << 18) || off >= (1LL << 18))
        return 0;
    uint32_t base = is64 ? 0xB5000000 : 0x35000000;
    return base | ((uint32_t)off & 0x7FFFF) << 5 | (uint32_t)(rt & 31);
}

uint32_t a64_insn_tbz(int rt, int bit, int is64, uint64_t target, uint64_t pc) {
    int64_t off = ((int64_t)target - (int64_t)pc) >> 2;
    if (off < -(1LL << 13) || off >= (1LL << 13))
        return 0;
    uint32_t base = 0x36000000; (void)is64;
    return base | ((uint32_t)((bit >> 5) & 1) << 31) |
           ((uint32_t)(bit & 0x1F) << 19) | ((uint32_t)off & 0x3FFF) << 5 |
           (uint32_t)(rt & 31);
}

uint32_t a64_insn_adrp(int rd, uint64_t target, uint64_t pc) {
    int64_t diff = (int64_t)((target & ~(uint64_t)0xFFF) - (pc & ~(uint64_t)0xFFF));
    int64_t imm21 = diff >> 12;
    if (imm21 < -(1LL << 20) || imm21 >= (1LL << 20))
        return 0;
    return 0x90000000 | ((uint32_t)imm21 & 3) << 29 |
           (((uint32_t)imm21 >> 2) & 0x7FFFF) << 5 | (uint32_t)(rd & 31);
}

uint32_t a64_insn_adr(int rd, uint64_t target, uint64_t pc) {
    int64_t imm = (int64_t)target - (int64_t)pc;
    if (imm < -(1LL << 20) || imm >= (1LL << 20))
        return 0;
    return 0x10000000 | ((uint32_t)imm & 3) << 29 |
           (((uint32_t)imm >> 2) & 0x7FFFF) << 5 | (uint32_t)(rd & 31);
}

uint32_t a64_insn_ldr_lit(int rt, int is64, uint64_t target, uint64_t pc) {
    int64_t off = ((int64_t)target - (int64_t)pc) >> 2;
    if (off < -(1LL << 18) || off >= (1LL << 18))
        return 0;
    uint32_t base = is64 ? 0x58000000 : 0x18000000;
    return base | ((uint32_t)off & 0x7FFFF) << 5 | (uint32_t)(rt & 31);
}

uint32_t a64_insn_mov_reg(int rd, int rm, int is64) {
    uint32_t base = is64 ? 0xAA000000 : 0x2A000000;
    return base | 0x3E0 | ((uint32_t)(rm & 31) << 16) | (uint32_t)(rd & 31);
}

uint32_t a64_insn_movz(int rd, uint16_t imm, int shift16, int is64) {
    uint32_t base = is64 ? 0xD2800000 : 0x52800000;
    return base | ((uint32_t)(shift16 & 3) << 21) | ((uint32_t)imm << 5) |
           (uint32_t)(rd & 31);
}

uint32_t a64_insn_add_imm(int rd, int rn, uint16_t imm, int is64) {
    uint32_t base = is64 ? 0x91000000 : 0x11000000;
    return base | ((uint32_t)(imm & 0xFFF) << 10) | ((uint32_t)(rn & 31) << 5) |
           (uint32_t)(rd & 31);
}

uint32_t a64_insn_sub_imm(int rd, int rn, uint16_t imm, int is64) {
    uint32_t base = is64 ? 0xD1000000 : 0x51000000;
    return base | ((uint32_t)(imm & 0xFFF) << 10) | ((uint32_t)(rn & 31) << 5) |
           (uint32_t)(rd & 31);
}

static uint32_t a64_ldstr_imm(uint32_t base, int rt, int rn, int64_t off,
                              int scale) {
    if (off >= 0 && (off & ((1 << scale) - 1)) == 0 &&
        (off >> scale) <= 0xFFF) {
        return base | ((uint32_t)(off >> scale) << 10) |
               ((uint32_t)(rn & 31) << 5) | (uint32_t)(rt & 31);
    }
    /* 退化为 stur/ldur(由调用方传对 base) */
    return 0;
}

uint32_t a64_insn_str_imm(int rt, int rn, int64_t off, int is64) {
    uint32_t b = a64_ldstr_imm(is64 ? 0xF9000000 : 0xB9000000, rt, rn, off,
                               is64 ? 3 : 2);
    if (b)
        return b;
    if (off < -256 || off > 255)
        return 0;
    return (is64 ? 0xF8000000 : 0xB8000000) | ((uint32_t)(off & 0x1FF) << 12) |
           ((uint32_t)(rn & 31) << 5) | (uint32_t)(rt & 31);
}

uint32_t a64_insn_ldr_imm(int rt, int rn, int64_t off, int is64) {
    uint32_t b = a64_ldstr_imm(is64 ? 0xF9400000 : 0xB9400000, rt, rn, off,
                               is64 ? 3 : 2);
    if (b)
        return b;
    if (off < -256 || off > 255)
        return 0;
    return (is64 ? 0xF8400000 : 0xB8400000) | ((uint32_t)(off & 0x1FF) << 12) |
           ((uint32_t)(rn & 31) << 5) | (uint32_t)(rt & 31);
}

/* str x/w, [rn, #imm]!(pre-index,写回 rn) */
uint32_t a64_insn_str_pre(int rt, int rn, int64_t off, int is64) {
    if (off < -256 || off > 255)
        return 0;
    uint32_t base = is64 ? 0xF8000C00 : 0xB8000C00; /* mode=11 pre */
    return base | ((uint32_t)(off & 0x1FF) << 12) | ((uint32_t)(rn & 31) << 5) |
           (uint32_t)(rt & 31);
}

/* ldr x/w, [rn], #imm(post-index,写回 rn) */
uint32_t a64_insn_ldr_post(int rt, int rn, int64_t off, int is64) {
    if (off < -256 || off > 255)
        return 0;
    uint32_t base = is64 ? 0xF8400400 : 0xB8400400;
    return base | ((uint32_t)(off & 0x1FF) << 12) | ((uint32_t)(rn & 31) << 5) |
           (uint32_t)(rt & 31);
}

uint32_t a64_insn_stp_pre(int rt1, int rt2, int rn, int64_t off, int is64) {
    int64_t s = off >> (is64 ? 3 : 2);
    if (off < -(1LL << 6) || off >= (1LL << 6) ||
        (off & ((1 << (is64 ? 3 : 2)) - 1)) != 0)
        return 0;
    uint32_t base = is64 ? 0xA9800000 : 0x29800000;
    return base | ((uint32_t)s & 0x7F) << 15 | ((uint32_t)(rt2 & 31) << 10) |
           ((uint32_t)(rn & 31) << 5) | (uint32_t)(rt1 & 31);
}

uint32_t a64_insn_ldp_post(int rt1, int rt2, int rn, int64_t off, int is64) {
    int64_t s = off >> (is64 ? 3 : 2);
    if (off < -(1LL << 6) || off >= (1LL << 6) ||
        (off & ((1 << (is64 ? 3 : 2)) - 1)) != 0)
        return 0;
    uint32_t base = is64 ? 0xA8C00000 : 0x28C00000;
    return base | ((uint32_t)s & 0x7F) << 15 | ((uint32_t)(rt2 & 31) << 10) |
           ((uint32_t)(rn & 31) << 5) | (uint32_t)(rt1 & 31);
}

uint32_t a64_insn_mrs_nzcv(int rd) {
    return 0xD53B4200 | (uint32_t)(rd & 31);
}

uint32_t a64_insn_msr_nzcv(int rn) {
    return 0xD51B4200 | (uint32_t)(rn & 31);
}

/* ------------------------- 重定位 ------------------------- */

int a64_is_pc_relative(const a64_insn_t *insn) {
    switch (insn->kind) {
    case A64_B:
    case A64_BL:
    case A64_B_COND:
    case A64_CBZ:
    case A64_TBZ:
    case A64_ADRP:
    case A64_ADR:
    case A64_LDR_LIT:
        return 1;
    default:
        return 0;
    }
}

int a64_relocate_displaced(uint64_t old_pc, uint32_t insn, uint64_t new_pc,
                           uint32_t *out) {
    a64_insn_t d;
    a64_decode(old_pc, insn, &d);
    if (!a64_is_pc_relative(&d)) {
        out[0] = insn;
        return 0;
    }
    switch (d.kind) {
    case A64_ADRP: {
        uint32_t e = a64_insn_adrp(d.rd, d.page, new_pc);
        if (!e)
            return -1;
        out[0] = e;
        return 1;
    }
    case A64_ADR: {
        uint32_t e = a64_insn_adr(d.rd, d.target, new_pc);
        if (!e)
            return -1;
        out[0] = e;
        return 1;
    }
    case A64_B: {
        uint32_t e = a64_insn_b(d.target, new_pc);
        if (!e)
            return -1;
        out[0] = e;
        return 1;
    }
    case A64_BL: {
        uint32_t e = a64_insn_bl(d.target, new_pc);
        if (!e)
            return -1;
        out[0] = e;
        return 1;
    }
    case A64_B_COND: {
        uint32_t e = a64_insn_b_cond(d.target, new_pc, (int)(insn & 15));
        if (!e)
            return -1;
        out[0] = e;
        return 1;
    }
    case A64_CBZ: {
        int cbnz = ((insn & 0x7E000000) == 0x35000000 ||
                    (insn & 0x7E000000) == 0xB5000000);
        uint32_t e = cbnz ? a64_insn_cbnz(d.rt, d.is64, d.target, new_pc)
                          : a64_insn_cbz(d.rt, d.is64, d.target, new_pc);
        if (!e)
            return -1;
        out[0] = e;
        return 1;
    }
    case A64_TBZ: {
        int tbnz = ((insn & 0x7E000000) == 0x37000000 ||
                    (insn & 0x7E000000) == 0xB7000000);
        uint32_t e = a64_insn_tbz(d.rt, (int)d.imm, d.is64, d.target, new_pc);
        if (tbnz)
            e ^= 0x01000000; /* tbz <-> tbnz 互转 */
        if (!e)
            return -1;
        out[0] = e;
        return 1;
    }
    case A64_LDR_LIT: {
        uint32_t e = a64_insn_ldr_lit(d.rt, d.is64, d.target, new_pc);
        if (!e)
            return -1;
        out[0] = e;
        return 1;
    }
    default:
        return -2;
    }
}
