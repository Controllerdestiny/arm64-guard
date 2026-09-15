/*
 * a64.h - AArch64 指令 编码 / 解码 / 重定位
 *
 * 仅覆盖本插桩引擎需要的指令子集(小端)。
 * 所有地址都是"运行时虚拟地址";编码器对 PC 相对指令按 (target, pc) 计算偏移。
 */
#ifndef A64_H
#define A64_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    A64_UNKNOWN = 0,   /* 未识别指令(保守处理)                          */
    A64_NOP,           /* nop / hint                                      */
    A64_RET,           /* ret xN(默认 x30)                                */
    A64_BR,            /* br xN                                           */
    A64_BLR,           /* blr xN(寄存器间接调用)                          */
    A64_B,             /* b imm26                                         */
    A64_BL,            /* bl imm26(直接调用)                              */
    A64_B_COND,        /* b.cond imm19                                    */
    A64_CBZ,           /* cbz/cbnz (w/x) imm19                            */
    A64_TBZ,           /* tbz/tbnz (w/x) imm14                            */
    A64_ADRP,          /* adrp xD, page                                   */
    A64_ADR,           /* adr xD, label                                   */
    A64_LDR_LIT,       /* ldr w/x, label(字面量)                          */
    A64_MOV_REG,       /* mov w/xD, w/xM (orr xzr)                        */
    A64_MOV_IMM,       /* movz/movk/movn w/xD, #imm                       */
    A64_ADD_IMM,       /* add/sub w/xD, w/xN, #imm                        */
    A64_STR_IMM,       /* str w/x, [base, #off] (unsigned)                */
    A64_LDR_IMM,       /* ldr w/x, [base, #off] (unsigned)                */
    A64_STUR,          /* stur/sturb/sturh w/x, [base, #off]              */
    A64_LDUR,          /* ldur/ldurb/ldurh/ldursb/ldursh w/x, [base,#off] */
    A64_STP,           /* stp w/x (unsigned/pre/post)                     */
    A64_LDP,           /* ldp w/x (unsigned/pre/post)                     */
    A64_STR_BH,        /* strb/strh w, [base, #off] (unsigned)            */
    A64_LDR_BH,        /* ldrb/ldrh/ldrsb/ldrsh w, [base, #off] (unsigned)*/
    A64_LDSTR_REG,     /* ldr/str w/x, [base, reg] (寄存器偏移)            */
    A64_MRS,           /* mrs xD, nzcv(及其它系统寄存器,按写 Rd 处理)     */
    A64_MSR,           /* msr nzcv, xN(及写系统寄存器,按无害处理)         */
    A64_OTHER          /* 其它写 Rd 的指令(按 kill Rd 处理)               */
} a64_kind_t;

typedef struct {
    a64_kind_t kind;
    uint32_t insn;
    uint64_t pc;        /* 指令地址                                        */
    int rd, rn, rm;     /* 寄存器编号(0-31,-1 表示无)                     */
    int rt, rt2;        /* 载荷指令的 rt/rt2                               */
    int is64;           /* 64 位变体                                       */
    int64_t imm;        /* 立即数(载荷偏移 / mov 立即数 / add 立即数)      */
    uint64_t target;    /* 分支/字面量/adr 解析后的目标地址                 */
    uint64_t page;      /* adrp 解析后的页地址                             */
    int mem_mode;       /* 0=偏移(无写回) 1=post-index 2=pre-index         */
    int mem_width;      /* 内存访问宽度 1/2/4/8(字节/半字/字/双字)         */
    int updates_rn;     /* pre/post 索引寻址:指令会写回 rn                 */
    int is_load;        /* 读内存                                          */
    int is_store;       /* 写内存                                          */
} a64_insn_t;

/* 解码一条指令(总是成功,kind 可能为 UNKNOWN/OTHER) */
void a64_decode(uint64_t pc, uint32_t insn, a64_insn_t *out);

/* ---------------- 编码器(全部返回 32 位指令字) ---------------- */
uint32_t a64_insn_nop(void);
uint32_t a64_insn_br(int rn);
uint32_t a64_insn_blr(int rn);
uint32_t a64_insn_b(uint64_t target, uint64_t pc);        /* 范围外返回 0 */
uint32_t a64_insn_bl(uint64_t target, uint64_t pc);
uint32_t a64_insn_b_cond(uint64_t target, uint64_t pc, int cond);
uint32_t a64_insn_cbz(int rt, int is64, uint64_t target, uint64_t pc);
uint32_t a64_insn_cbnz(int rt, int is64, uint64_t target, uint64_t pc);
uint32_t a64_insn_tbz(int rt, int bit, int is64, uint64_t target, uint64_t pc);
uint32_t a64_insn_adrp(int rd, uint64_t target, uint64_t pc);
uint32_t a64_insn_adr(int rd, uint64_t target, uint64_t pc);
uint32_t a64_insn_ldr_lit(int rt, int is64, uint64_t target, uint64_t pc);
uint32_t a64_insn_mov_reg(int rd, int rm, int is64);
uint32_t a64_insn_movz(int rd, uint16_t imm, int shift16, int is64);
uint32_t a64_insn_movk(int rd, uint16_t imm, int shift16, int is64);
uint32_t a64_insn_add_imm(int rd, int rn, uint16_t imm, int is64);
uint32_t a64_insn_sub_imm(int rd, int rn, uint16_t imm, int is64);
uint32_t a64_insn_add_reg(int rd, int rn, int rm);   /* add xD, xN, xM      */
uint32_t a64_insn_sub_reg(int rd, int rn, int rm);   /* sub xD, xN, xM      */
uint32_t a64_insn_str_imm(int rt, int rn, int64_t off, int is64);
uint32_t a64_insn_ldr_imm(int rt, int rn, int64_t off, int is64);
uint32_t a64_insn_str_pre(int rt, int rn, int64_t off, int is64);  /* str, [rn, #off]! */
uint32_t a64_insn_ldr_post(int rt, int rn, int64_t off, int is64); /* ldr, [rn], #off   */
uint32_t a64_insn_stp_pre(int rt1, int rt2, int rn, int64_t off, int is64);
uint32_t a64_insn_ldp_post(int rt1, int rt2, int rn, int64_t off, int is64);
uint32_t a64_insn_mrs_nzcv(int rd);
uint32_t a64_insn_msr_nzcv(int rn);

/* 判断一条指令是否 PC 相对(需要重定位) */
int a64_is_pc_relative(const a64_insn_t *insn);

/*
 * 把一条被搬移的指令(old_pc 处)重定位到 new_pc 处执行。
 * 返回: 1 = 已重编码写入 out[0](PC 相对且可重编码)
 *       0 = 非 PC 相对,原样搬移(out[0] = insn)
 *      -1 = PC 相对但超出编码范围(调用方需用 绝对跳转/字面量 方案,见 instr.c)
 *      -2 = PC 相对但本实现不支持(调用方应中止本次补丁)
 */
int a64_relocate_displaced(uint64_t old_pc, uint32_t insn, uint64_t new_pc,
                           uint32_t *out);

#ifdef __cplusplus
}
#endif

#endif /* A64_H */
