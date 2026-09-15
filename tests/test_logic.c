/*
 * test_logic.c - 宿主机逻辑测试(编译为 x86_64-windows-gnu 用 zig 运行)
 *
 * 覆盖:
 *   1. a64 编码/解码/重定位 自检(已知常量 + 往返)
 *   2. ELF 解析:main / printf PLT / GOT
 *   3. 数据流分析:main 参数在守卫点处的存活位置
 *   4. 插桩规划:call-guard / block-guard 的补丁字节与 trampoline 字节
 *
 * 输出:机器可读文本 build/plan_dump.txt,由 tools/verify.py
 * 用 capstone(反汇编交叉验证)+ unicorn(端到端执行)二次验证。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "a64.h"
#include "elf64.h"
#include "analysis.h"
#include "instr_internal.h"

/* 模拟的运行时布局(与 verify.py / unicorn 保持一致) */
#define RUNTIME_BASE 0x4000000000ull
#define TRAMP_BASE   0x4001000000ull
#define CHECK_ADDR   0x6000001000ull
#define CALLEE_ADDR  0x6000002000ull

static int g_fail = 0;

static void chk(int cond, const char *name) {
    if (cond) {
        printf("  [PASS] %s\n", name);
    } else {
        printf("  [FAIL] %s\n", name);
        g_fail = 1;
    }
}

/* ---------------- 解码语料(NDK clang 汇编所得,ground truth) ---------------- */

typedef struct {
    uint32_t w;
    a64_kind_t kind;
    int rd, rn, rm, rt, rt2;
    int is64;
    int64_t imm;
    int mem_mode, mem_width;
    int is_load, is_store;
} corpus_case_t;

static void test_decode_corpus(void) {
    printf("== a64 解码语料校验(与 NDK clang 编码逐一对照) ==\n");
    corpus_case_t cases[] = {
        /* stur/ldur 家族(imm9) */
        { 0xF80083E0, A64_STUR, -1, 31, -1, 0, -1, 1, 8, 0, 8, 0, 1 },
        { 0xB81FC3E1, A64_STUR, -1, 31, -1, 1, -1, 0, -4, 0, 4, 0, 1 },
        { 0xF84103E2, A64_LDUR, -1, 31, -1, 2, -1, 1, 16, 0, 8, 1, 0 },
        { 0xB85F83E3, A64_LDUR, -1, 31, -1, 3, -1, 0, -8, 0, 4, 1, 0 },
        { 0x380013E4, A64_STUR, -1, 31, -1, 4, -1, 0, 1, 0, 1, 0, 1 },
        { 0x780023E5, A64_STUR, -1, 31, -1, 5, -1, 0, 2, 0, 2, 0, 1 },
        { 0x384033E6, A64_LDUR, -1, 31, -1, 6, -1, 0, 3, 0, 1, 1, 0 },
        { 0x784043E7, A64_LDUR, -1, 31, -1, 7, -1, 0, 4, 0, 2, 1, 0 },
        { 0x38C053E8, A64_LDUR, -1, 31, -1, 8, -1, 0, 5, 0, 1, 1, 0 },
        { 0xB88183E9, A64_LDUR, -1, 31, -1, 9, -1, 1, 24, 0, 4, 1, 0 },
        /* pre/post 索引 */
        { 0xF81F0FE0, A64_STUR, -1, 31, -1, 0, -1, 1, -16, 3, 8, 0, 1 },
        { 0xF84107E1, A64_LDUR, -1, 31, -1, 1, -1, 1, 16, 1, 8, 1, 0 },
        { 0xB8008FA2, A64_STUR, -1, 29, -1, 2, -1, 0, 8, 3, 4, 0, 1 },
        { 0xB84047A3, A64_LDUR, -1, 29, -1, 3, -1, 0, 4, 1, 4, 1, 0 },
        /* stp/ldp */
        { 0xA9BF07E0, A64_STP, -1, 31, -1, 0, 1, 1, -16, 2, 8, 0, 1 },
        { 0xA8C10FE2, A64_LDP, -1, 31, -1, 2, 3, 1, 16, 1, 8, 1, 0 },
        { 0xA9BF7BFD, A64_STP, -1, 31, -1, 29, 30, 1, -16, 2, 8, 0, 1 },
        { 0xA8C17BFD, A64_LDP, -1, 31, -1, 29, 30, 1, 16, 1, 8, 1, 0 },
        /* 字节/半字 imm12 */
        { 0x390017E4, A64_STR_BH, -1, 31, -1, 4, -1, 0, 5, 0, 1, 0, 1 },
        { 0x39401BE5, A64_LDR_BH, -1, 31, -1, 5, -1, 0, 6, 0, 1, 1, 0 },
        { 0x790013E6, A64_STR_BH, -1, 31, -1, 6, -1, 0, 8, 0, 2, 0, 1 },
        { 0x794017E7, A64_LDR_BH, -1, 31, -1, 7, -1, 0, 10, 0, 2, 1, 0 },
        { 0x39C033E8, A64_LDR_BH, -1, 31, -1, 8, -1, 0, 12, 0, 1, 1, 0 },
        { 0x79C01FE9, A64_LDR_BH, -1, 31, -1, 9, -1, 0, 14, 0, 2, 1, 0 },
        /* 寄存器偏移 */
        { 0xF8226820, A64_LDSTR_REG, -1, 1, 2, 0, -1, 1, 0, 0, 8, 0, 1 },
        { 0xF8656883, A64_LDSTR_REG, -1, 4, 5, 3, -1, 1, 0, 0, 8, 1, 0 },
        { 0xB86868E6, A64_LDSTR_REG, -1, 7, 8, 6, -1, 0, 0, 0, 4, 1, 0 },
        { 0x382B6949, A64_LDSTR_REG, -1, 10, 11, 9, -1, 0, 0, 0, 1, 0, 1 },
        { 0x386E69AC, A64_LDSTR_REG, -1, 13, 14, 12, -1, 0, 0, 0, 1, 1, 0 },
        { 0xB8B16A0F, A64_LDSTR_REG, -1, 16, 17, 15, -1, 1, 0, 0, 4, 1, 0 },
        /* mov 别名(反向操作数形式) */
        { 0xAA0103E0, A64_MOV_REG, 0, -1, 1, -1, -1, 1, 0, 0, 0, 0, 0 },
        { 0xAA1F03E2, A64_MOV_REG, 2, -1, 31, -1, -1, 1, 0, 0, 0, 0, 0 },
        { 0xAA1F0083, A64_MOV_REG, 3, -1, 4, -1, -1, 1, 0, 0, 0, 0, 0 },
        { 0x2A0603E5, A64_MOV_REG, 5, -1, 6, -1, -1, 0, 0, 0, 0, 0, 0 },
        /* 其它写 Rd(保守) */
        { 0xD37DF020, A64_OTHER, 0, -1, -1, -1, -1, 0, 0, 0, 0, 0, 0 },
        { 0x9A840062, A64_OTHER, 2, -1, -1, -1, -1, 0, 0, 0, 0, 0, 0 },
        { 0x8B0700C5, A64_OTHER, 5, -1, -1, -1, -1, 0, 0, 0, 0, 0, 0 },
        { 0xCB0A0128, A64_OTHER, 8, -1, -1, -1, -1, 0, 0, 0, 0, 0, 0 },
        { 0x9B010811, A64_OTHER, 17, -1, -1, -1, -1, 0, 0, 0, 0, 0, 0 },
        { 0x93407C83, A64_OTHER, 3, -1, -1, -1, -1, 0, 0, 0, 0, 0, 0 },
        { 0xB1001420, A64_OTHER, 0, -1, -1, -1, -1, 0, 0, 0, 0, 0, 0 },
        { 0xEB03005F, A64_OTHER, 31, -1, -1, -1, -1, 0, 0, 0, 0, 0, 0 },
        /* 大偏移 ldr */
        { 0xF9480FE1, A64_LDR_IMM, -1, 31, -1, 1, -1, 1, 4120, 0, 8, 1, 0 },
    };
    int fails = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        corpus_case_t *cc = &cases[i];
        a64_insn_t d;
        a64_decode(0x1000 + (uint64_t)i * 4, cc->w, &d);
        int ok = d.kind == cc->kind && d.rd == cc->rd && d.rn == cc->rn &&
                 d.rm == cc->rm && d.rt == cc->rt && d.rt2 == cc->rt2 &&
                 d.is64 == cc->is64 && d.imm == cc->imm &&
                 d.mem_mode == cc->mem_mode && d.mem_width == cc->mem_width &&
                 d.is_load == cc->is_load && d.is_store == cc->is_store;
        if (!ok) {
            fails++;
            printf("  [FAIL] %08x: kind=%d(exp %d) rd=%d(exp %d) rn=%d(exp %d) "
                   "rm=%d(exp %d) rt=%d(exp %d) rt2=%d(exp %d) is64=%d(exp %d) "
                   "imm=%lld(exp %lld) mode=%d(exp %d) width=%d(exp %d) "
                   "load=%d(exp %d) store=%d(exp %d)\n",
                   cc->w, (int)d.kind, (int)cc->kind, d.rd, cc->rd, d.rn, cc->rn,
                   d.rm, cc->rm, d.rt, cc->rt, d.rt2, cc->rt2, d.is64, cc->is64,
                   (long long)d.imm, (long long)cc->imm, d.mem_mode,
                   cc->mem_mode, d.mem_width, cc->mem_width, d.is_load,
                   cc->is_load, d.is_store, cc->is_store);
        }
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "解码语料 %zu 条全部一致",
             sizeof(cases) / sizeof(cases[0]));
    chk(fails == 0, buf);
    if (fails) {
        g_fail = 1;
    }
}

/* ---------------- 数据流分析单元测试 ---------------- */

typedef struct {
    const uint32_t *words;
    size_t n;
} ram_t;

static uint32_t fetch_ram(void *ctx, uint64_t addr) {
    ram_t *r = (ram_t *)ctx;
    if (addr < 0x1000)
        return 0;
    uint64_t idx = (addr - 0x1000) / 4;
    if (idx >= r->n)
        return 0;
    return r->words[idx];
}

/* 在合成指令序列 [words, n) 的 guard 索引处做多参数分析 */
static int locate_ram(const uint32_t *words, size_t n, size_t guard_idx,
                      a64_loc_t *locs, int *nfound) {
    ram_t r = { words, n };
    return analysis_locate_args(fetch_ram, &r, 0x1000,
                                0x1000 + (uint64_t)n * 4,
                                0x1000 + (uint64_t)guard_idx * 4, locs,
                                nfound);
}

static void test_analysis_flow(void) {
    printf("== 数据流分析单元测试(复杂指令序列) ==\n");

    /* 1. pre-index 压栈 + 从新 sp 读回 + 杀 x0 */
    {
        uint32_t w[] = {
            a64_insn_str_pre(0, 31, -16, 1),   /* str x0, [sp, #-16]! */
            a64_insn_mov_reg(0, 31, 1),        /* mov x0, xzr          */
            a64_insn_ldr_imm(1, 31, 0, 1),     /* ldr x1, [sp, #0]     */
            a64_insn_nop(),                    /* 守卫点:x0 已死,x1=arg0 */
        };
        a64_loc_t locs[ANALYSIS_NARGS];
        int nf = 0;
        int rc = locate_ram(w, 4, 3, locs, &nf);
        chk(rc == 0 && nf >= 1, "pre-index 压栈后从 [sp,#0] 读回(arg0 存活)");
        chk(locs[0].kind == LOC_REG && locs[0].reg == 1,
            "pre-index 场景 arg0 位于 x1");
    }

    /* 2. post-index 压栈 + 从 [sp,#-16] 读回 */
    {
        uint32_t s2[] = {
            0xF80107E0,                        /* str x0, [sp], #16 */
            a64_insn_mov_reg(0, 31, 1),        /* mov x0, xzr          */
            0xF85F03E1,                        /* ldur x1, [sp, #-16]  */
            a64_insn_nop(),                    /* 守卫点 */
        };
        a64_loc_t locs[ANALYSIS_NARGS];
        int nf = 0;
        int rc = locate_ram(s2, 4, 3, locs, &nf);
        chk(rc == 0 && nf >= 1, "post-index 压栈后从 [sp,#-16] 读回(arg0 存活)");
        chk(locs[0].kind == LOC_REG && locs[0].reg == 1,
            "post-index 场景 arg0 位于 x1");
    }

    /* 3. 字节存储不登记槽位:strb 后 ldr 读不到参数 */
    {
        uint32_t w[] = {
            0x390023E0,                        /* strb w0, [sp, #8] */
            a64_insn_mov_reg(0, 31, 1),        /* mov x0, xzr        */
            a64_insn_ldr_imm(1, 31, 8, 1),     /* ldr x1, [sp, #8]   */
            a64_insn_nop(),                    /* 守卫点 */
        };
        a64_loc_t locs[ANALYSIS_NARGS];
        int nf = 0;
        int rc = locate_ram(w, 4, 3, locs, &nf);
        chk(rc == 0, "字节存储场景分析成功");
        chk(locs[0].kind == LOC_UNKNOWN,
            "strb 部分宽度存储后 arg0 不可恢复(不产生假槽位)");
    }

    /* 4. callee-saved 基址槽:x19 基址可用 */
    {
        uint32_t w[] = {
            a64_insn_str_imm(0, 19, 8, 1),     /* str x0, [x19, #8] */
            a64_insn_mov_reg(0, 31, 1),        /* mov x0, xzr        */
            a64_insn_nop(),                    /* 守卫点 */
        };
        a64_loc_t locs[ANALYSIS_NARGS];
        int nf = 0;
        int rc = locate_ram(w, 3, 2, locs, &nf);
        chk(rc == 0 && nf >= 1, "x19 基址槽位可恢复");
        chk(locs[0].kind == LOC_SLOT && locs[0].base_reg == 19 &&
                locs[0].off == 8,
            "x19 槽位 [x19, #8] 被正确报告");
    }

    /* 5. 基址寄存器被改写 -> 槽位必须失效(旧实现会报告错误槽位) */
    {
        uint32_t w[] = {
            a64_insn_mov_reg(19, 0, 1),        /* mov x19, x0 */
            a64_insn_str_imm(0, 19, 8, 1),     /* str x0, [x19, #8] */
            a64_insn_mov_reg(0, 31, 1),        /* mov x0, xzr        */
            a64_insn_add_imm(19, 19, 16, 1),   /* add x19, x19, #16  */
            a64_insn_nop(),                    /* 守卫点:基址已改写 */
        };
        a64_loc_t locs[ANALYSIS_NARGS];
        int nf = 0;
        int rc = locate_ram(w, 5, 4, locs, &nf);
        chk(rc == 0, "基址改写场景分析成功");
        chk(locs[0].kind == LOC_UNKNOWN,
            "x19 被改写后其槽位失效(arg0 不可恢复,而非错误位置)");
    }

    /* 6. bl 保留 callee-saved 槽位 */
    {
        uint32_t w[] = {
            a64_insn_mov_reg(19, 0, 1),        /* mov x19, x0 */
            a64_insn_bl(0x5000000, 0x1008),    /* bl 远处 */
            a64_insn_str_imm(19, 31, 8, 1),    /* str x19, [sp, #8] */
            a64_insn_ldr_imm(0, 31, 8, 1),     /* ldr x0, [sp, #8]  */
            a64_insn_nop(),                    /* 守卫点 */
        };
        a64_loc_t locs[ANALYSIS_NARGS];
        int nf = 0;
        int rc = locate_ram(w, 5, 4, locs, &nf);
        chk(rc == 0 && nf >= 1, "bl 后 callee-saved 槽位链仍存活");
        chk(locs[0].kind == LOC_REG && locs[0].reg == 0,
            "bl 后 arg0 经 x19 压栈读回 x0");
    }

    /* 7. add x29, sp, #0 后经 x29 压栈 */
    {
        uint32_t w[] = {
            a64_insn_add_imm(29, 31, 0, 1),    /* add x29, sp, #0 */
            a64_insn_str_imm(0, 29, -8, 1),    /* stur x0, [x29, #-8] */
            a64_insn_mov_reg(0, 31, 1),        /* mov x0, xzr        */
            a64_insn_nop(),                    /* 守卫点 */
        };
        a64_loc_t locs[ANALYSIS_NARGS];
        int nf = 0;
        int rc = locate_ram(w, 4, 3, locs, &nf);
        chk(rc == 0 && nf >= 1, "x29 帧基换算后槽位可恢复");
        chk(locs[0].kind == LOC_SLOT && locs[0].base_reg == 29 &&
                locs[0].off == -8,
            "arg0 位于 [x29, #-8]");
    }

    /* 8. 大栈帧偏移(>4095) */
    {
        uint32_t w[] = {
            a64_insn_sub_imm(31, 31, 4120, 1), /* sub sp, sp, #4120 */
            a64_insn_str_imm(0, 31, 4120, 1),  /* str x0, [sp, #4120] */
            a64_insn_mov_reg(0, 31, 1),        /* mov x0, xzr        */
            a64_insn_nop(),                    /* 守卫点 */
        };
        a64_loc_t locs[ANALYSIS_NARGS];
        int nf = 0;
        int rc = locate_ram(w, 4, 3, locs, &nf);
        chk(rc == 0 && nf >= 1, "大帧偏移槽位可恢复");
        chk(locs[0].kind == LOC_SLOT && locs[0].base_reg == 31 &&
                locs[0].off == 4120,
            "arg0 位于 [sp, #4120]");
    }

    /* 9. ldr 字面量必须杀 rt(旧实现漏杀 → 错误位置) */
    {
        uint32_t w[] = {
            a64_insn_mov_reg(9, 0, 1),         /* mov x9, x0 */
            a64_insn_ldr_lit(9, 1, 0x2000, 0x1004), /* ldr x9, [pc, #8] */
            a64_insn_mov_reg(0, 31, 1),        /* mov x0, xzr        */
            a64_insn_nop(),                    /* 守卫点 */
        };
        a64_loc_t locs[ANALYSIS_NARGS];
        int nf = 0;
        int rc = locate_ram(w, 4, 3, locs, &nf);
        chk(rc == 0, "ldr 字面量场景分析成功");
        chk(locs[0].kind == LOC_UNKNOWN,
            "ldr 字面量后 x9 被杀,arg0 不可恢复");
    }

    /* 10. REG 源与 SLOT 源混合(暂存不互相污染):arg0=槽,arg1=x9 */
    {
        uint32_t w[] = {
            a64_insn_str_imm(0, 31, 8, 1),     /* str x0, [sp, #8]  -> arg0 槽 */
            a64_insn_mov_reg(9, 1, 1),         /* mov x9, x1        -> arg1 x9 */
            a64_insn_mov_reg(0, 31, 1),        /* mov x0, xzr */
            a64_insn_mov_reg(1, 31, 1),        /* mov x1, xzr */
            a64_insn_nop(),                    /* 守卫点 */
        };
        a64_loc_t locs[ANALYSIS_NARGS];
        int nf = 0;
        int rc = locate_ram(w, 5, 4, locs, &nf);
        chk(rc == 0 && nf >= 2, "混合暂存场景两参数均可恢复");
        chk(locs[0].kind == LOC_SLOT && locs[0].base_reg == 31 &&
                locs[0].off == 8,
            "arg0 位于 [sp, #8]");
        chk(locs[1].kind == LOC_REG && locs[1].reg == 9,
            "arg1 位于 x9");
    }
}

static void test_a64_self(void) {
    printf("== a64 编码/解码自检 ==\n");

    /* 已知常量 */
    chk(a64_insn_stp_pre(29, 30, 31, -16, 1) == 0xA9BF7BFD,
        "stp x29, x30, [sp, #-16]! == 0xA9BF7BFD");
    chk(a64_insn_mov_reg(19, 0, 1) == 0xAA0003F3, "mov x19, x0 == 0xAA0003F3");
    chk(a64_insn_mov_reg(0, 1, 0) == 0x2A0103E0, "mov w0, w1 == 0x2A0103E0");
    chk(a64_insn_br(16) == 0xD61F0200, "br x16 == 0xD61F0200");
    chk(a64_insn_blr(16) == 0xD63F0200, "blr x16 == 0xD63F0200");
    chk(a64_insn_nop() == 0xD503201F, "nop == 0xD503201F");
    chk(a64_insn_mrs_nzcv(8) == 0xD53B4208, "mrs x8, nzcv");
    chk(a64_insn_msr_nzcv(8) == 0xD51B4208, "msr nzcv, x8");
    chk(a64_insn_ldr_lit(16, 1, 0x1008, 0x1000) == 0x58000050,
        "ldr x16, [pc, #8] == 0x58000050");

    /* 解码往返 */
    {
        uint64_t pc = 0x12340000;
        struct {
            uint32_t w;
            a64_kind_t kind;
            uint64_t expect;
            int is_adrp; /* 1 = 结果在 page 字段 */
        } cases[] = {
            { a64_insn_b(0x12348000, pc), A64_B, 0x12348000, 0 },
            { a64_insn_bl(0x12350000, pc), A64_BL, 0x12350000, 0 },
            { a64_insn_cbz(3, 0, 0x12348000, pc), A64_CBZ, 0x12348000, 0 },
            { a64_insn_cbnz(5, 1, 0x12340040, pc), A64_CBZ, 0x12340040, 0 },
            { a64_insn_b_cond(0x12340100, pc, 0), A64_B_COND, 0x12340100,
              0 },
            { a64_insn_tbz(7, 3, 1, 0x12340080, pc), A64_TBZ, 0x12340080,
              0 },
            { a64_insn_adrp(0, 0x12345000, pc), A64_ADRP, 0x12345000, 1 },
            { a64_insn_adr(1, 0x12340020, pc), A64_ADR, 0x12340020, 0 },
            { a64_insn_ldr_lit(2, 0, 0x12341000, pc), A64_LDR_LIT,
              0x12341000, 0 },
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            a64_insn_t d;
            a64_decode(pc, cases[i].w, &d);
            uint64_t got = cases[i].is_adrp ? d.page : d.target;
            char buf[64];
            snprintf(buf, sizeof(buf), "decode roundtrip #%zu (kind=%d)", i,
                     (int)cases[i].kind);
            chk(d.kind == cases[i].kind && got == cases[i].expect, buf);
            if (d.kind != cases[i].kind || got != cases[i].expect)
                printf("    dbg: w=%08x kind=%d expect_kind=%d got=%llx "
                       "expect=%llx page=%llx\n",
                       cases[i].w, (int)d.kind, (int)cases[i].kind,
                       (unsigned long long)got,
                       (unsigned long long)cases[i].expect,
                       (unsigned long long)d.page);
        }
    }

    /* 重定位(bl 目标必须位于 ±128MB 内) */
    {
        uint32_t out;
        uint32_t bl = a64_insn_bl(0x1010000, 0x1000); /* 距离 16MB */
        int r = a64_relocate_displaced(0x1000, bl, 0x5000, &out);
        chk(r == 1, "relocate bl (in range)");
        if (r == 1) {
            a64_insn_t d;
            a64_decode(0x5000, out, &d);
            chk(d.target == 0x1010000, "relocated bl target preserved");
        }
        /* 超范围 bl */
        uint32_t bl2 = a64_insn_bl(0x1010000, 0x1000);
        r = a64_relocate_displaced(0x1000, bl2, 0x5000000000ull, &out);
        chk(r == -1, "relocate bl out of range -> -1 (caller uses ldr+blr)");
        /* 非 PC 相对原样 */
        r = a64_relocate_displaced(0x1000, 0xA9BF7BFD, 0x5000, &out);
        chk(r == 0 && out == 0xA9BF7BFD, "non-pc-relative moved verbatim");
    }
}

/* ---------------- 取指(镜像) ---------------- */

static uint32_t fetch_img(void *ctx, uint64_t addr) {
    const elf64_module_t *m = (const elf64_module_t *)ctx;
    ptrdiff_t off = elf64_va_to_offset(m, addr);
    if (off < 0)
        return 0;
    if ((size_t)off + 4 > m->size)
        return 0;
    const uint8_t *img = m->image ? m->image : m->base;
    uint32_t w;
    memcpy(&w, img + off, 4);
    return w;
}

static uint8_t *read_file(const char *path, size_t *sz) {
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = (uint8_t *)malloc((size_t)n);
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
        fclose(f);
        free(buf);
        return NULL;
    }
    fclose(f);
    *sz = (size_t)n;
    return buf;
}

/* 找 caller 范围(st_size 优先,否则扫到最后一个 ret) */
static uint64_t find_end(const elf64_module_t *m, uint64_t va, uint64_t sz) {
    if (sz > 0)
        return va + sz;
    uint64_t last = va + 4;
    for (uint64_t pc = va; pc < va + 8192 * 4; pc += 4) {
        uint32_t w = fetch_img((void *)m, pc);
        if (!w)
            break;
        a64_insn_t d;
        a64_decode(pc, w, &d);
        if (d.kind == A64_RET)
            last = pc + 4;
    }
    return last;
}

static void print_hex(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++)
        printf("%02x", b[i]);
}

static void dump_hex(FILE *f, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++)
        fprintf(f, "%02x", b[i]);
}

/* ---------------- 目标模块测试 ---------------- */

static int test_target(const char *path, const char *tag, int want_block,
                       const char *caller_name, FILE *dump) {
    size_t sz = 0;
    uint8_t *img = read_file(path, &sz);
    if (!img) {
        printf("[FAIL] cannot read %s\n", path);
        return -1;
    }
    elf64_module_t m;
    if (elf64_module_init(&m, (void *)(uintptr_t)RUNTIME_BASE, img, sz) != 0) {
        printf("[FAIL] %s not a valid AArch64 ELF\n", path);
        return -1;
    }

    uint64_t main_va, main_sz = 0;
    if (elf64_find_symbol(&m, caller_name, &main_va, &main_sz) != 0) {
        printf("[FAIL] symbol '%s' not found in %s\n", caller_name, path);
        return -1;
    }
    uint64_t main_end = find_end(&m, main_va, main_sz);
    printf("== %s ==\n", tag);
    printf("%s @ %#llx size=%llu end=%#llx\n", caller_name,
           (unsigned long long)main_va, (unsigned long long)main_sz,
           (unsigned long long)main_end);

    /* 反汇编导出(capstone 交叉验证用) */
    for (uint64_t pc = main_va; pc + 4 <= main_end; pc += 4) {
        uint32_t w = fetch_img(&m, pc);
        fprintf(dump, "DISA %s %016llx %08x\n", tag,
                (unsigned long long)pc, w);
    }

    uint64_t plt_va, got_va;
    if (elf64_find_plt(&m, "printf", &plt_va, &got_va) != 0) {
        printf("[FAIL] printf PLT not found in %s\n", path);
        return -1;
    }
    printf("printf PLT @ %#llx GOT @ %#llx\n",
           (unsigned long long)plt_va, (unsigned long long)got_va);
    fprintf(dump, "INFO %s main=%016llx main_end=%016llx plt=%016llx got=%016llx\n",
            tag, (unsigned long long)main_va, (unsigned long long)main_end,
            (unsigned long long)plt_va, (unsigned long long)got_va);

    if (want_block) {
        /* 找 movz x9, #0x6d0 / #0x6d1 标记 */
        uint64_t bstart = 0, bend = 0;
        int seen = 0;
        for (uint64_t pc = main_va; pc + 4 <= main_end; pc += 4) {
            uint32_t w = fetch_img(&m, pc);
            a64_insn_t d;
            a64_decode(pc, w, &d);
            if (d.kind == A64_MOV_IMM && d.rd == 9 && (d.imm & 0xFFFF) == 0x6d0 &&
                !seen) {
                bstart = pc + 4;
                seen = 1;
            } else if (d.kind == A64_MOV_IMM && d.rd == 9 &&
                       (d.imm & 0xFFFF) == 0x6d1 && seen) {
                bend = pc;
                break;
            }
        }
        if (!bstart || !bend) {
            printf("[FAIL] block markers not found in %s\n", path);
            return -1;
        }
        printf("block [%#llx, %#llx) len=%llu\n", (unsigned long long)bstart,
               (unsigned long long)bend,
               (unsigned long long)(bend - bstart));

        /* 分析:参数位置 */
        a64_loc_t loc;
        int rc = analysis_locate_first_arg(fetch_img, &m, main_va, main_end,
                                           bstart, &loc);
        printf("analysis(block) rc=%d loc=", rc);
        if (rc == 0) {
            if (loc.kind == LOC_REG)
                printf("REG x%d\n", loc.reg);
            else
                printf("SLOT [x%d, #%lld] is64=%d\n", loc.base_reg,
                       (long long)loc.off, loc.is64);
            fprintf(dump, "LOC %s block %d %d %lld %d\n", tag, loc.kind,
                    loc.kind == LOC_REG ? loc.reg : loc.base_reg,
                    (long long)loc.off, loc.is64);
        } else {
            printf("UNKNOWN\n");
        }

        /* 多参数分析:入口 x0~x7 全部存活位置(实例方法时 x0=this) */
        {
            a64_loc_t locs[ANALYSIS_NARGS];
            int nfound = 0;
            analysis_locate_args(fetch_img, &m, main_va, main_end, bstart,
                                 locs, &nfound);
            for (int k = 0; k < ANALYSIS_NARGS; k++) {
                fprintf(dump, "ARGS %s %d %d %d %lld %d\n", tag, k,
                        (int)locs[k].kind,
                        locs[k].kind == LOC_REG ? locs[k].reg
                                                : locs[k].base_reg,
                        (long long)locs[k].off, locs[k].is64);
            }
            printf("args recovered: %d/8\n", nfound);
        }

        /* 规划 block-guard */
        instr_plan_t plan;
        rc = instr_plan_guard(&m, main_va, main_end, bstart, 0, bend,
                              CHECK_ADDR, 0, TRAMP_BASE, 0, &plan);
        printf("plan(block) rc=%d patch_len=%d tramp_words=%zu\n", rc,
               plan.patch_len, plan.tramp_words);
        if (rc == INSTR_OK) {
            printf("  patch: ");
            print_hex(plan.patch, (size_t)plan.patch_len);
            printf("\n  orig : ");
            print_hex(plan.orig, (size_t)plan.patch_len);
            printf("\n  tramp:");
            for (size_t i = 0; i < plan.tramp_words; i++)
                printf(" %08x", plan.tramp[i]);
            printf("\n");
            fprintf(dump, "PLAN %s block %016llx %d ",
                    tag, (unsigned long long)bstart, plan.patch_len);
            dump_hex(dump, plan.patch, (size_t)plan.patch_len);
            fprintf(dump, " %zu ", plan.tramp_words);
            for (size_t i = 0; i < plan.tramp_words; i++)
                fprintf(dump, "%08x", plan.tramp[i]);
            fprintf(dump, "\n");
        }

        /* 入口快照补丁规划(供 verify_snap.py 端到端验证) */
        {
            instr_plan_t ep;
            rc = instr_plan_entry_snapshot(&m, main_va, bend,
                                           TRAMP_BASE + 0x1000,
                                           TRAMP_BASE + 0x2000, 0, 0, &ep);
            printf("plan(entry snap) rc=%d patch_len=%d tramp_words=%zu\n", rc,
                   ep.patch_len, ep.tramp_words);
            if (rc == INSTR_OK) {
                fprintf(dump, "PLAN %s entry %016llx %d ", tag,
                        (unsigned long long)main_va, ep.patch_len);
                dump_hex(dump, ep.patch, (size_t)ep.patch_len);
                fprintf(dump, " %zu ", ep.tramp_words);
                for (size_t i = 0; i < ep.tramp_words; i++)
                    fprintf(dump, "%08x", ep.tramp[i]);
                fprintf(dump, "\n");
            }
        }

        /* 链式共存规划:入口已有 Dobby 形态 hook 时,快照 trampoline
         * 保存参数后直接跳进现有 hook 的 trampoline(不再重放入口指令) */
        {
            instr_plan_t ep;
            rc = instr_plan_entry_snapshot(&m, main_va, bend,
                                           TRAMP_BASE + 0x1000,
                                           TRAMP_BASE + 0x2000,
                                           TRAMP_BASE + 0x3000, 16, &ep);
            printf("plan(entry snap chained) rc=%d patch_len=%d "
                   "tramp_words=%zu\n", rc, ep.patch_len, ep.tramp_words);
            if (rc == INSTR_OK) {
                fprintf(dump, "PLAN %s entrychain %016llx %d ", tag,
                        (unsigned long long)main_va, ep.patch_len);
                dump_hex(dump, ep.patch, (size_t)ep.patch_len);
                fprintf(dump, " %zu ", ep.tramp_words);
                for (size_t i = 0; i < ep.tramp_words; i++)
                    fprintf(dump, "%08x", ep.tramp[i]);
                fprintf(dump, "\n");
            }
        }

        /* 快照模式守卫规划(跳过数据流分析,参数从快照区读) */
        {
            instr_plan_t sp;
            rc = instr_plan_guard(&m, main_va, main_end, bstart, 0, bend,
                                  CHECK_ADDR, 0, TRAMP_BASE,
                                  TRAMP_BASE + 0x1000, &sp);
            printf("plan(block snap) rc=%d patch_len=%d tramp_words=%zu\n",
                   rc, sp.patch_len, sp.tramp_words);
            if (rc == INSTR_OK) {
                fprintf(dump, "PLAN %s snapsnap %016llx %d ", tag,
                        (unsigned long long)bstart, sp.patch_len);
                dump_hex(dump, sp.patch, (size_t)sp.patch_len);
                fprintf(dump, " %zu ", sp.tramp_words);
                for (size_t i = 0; i < sp.tramp_words; i++)
                    fprintf(dump, "%08x", sp.tramp[i]);
                fprintf(dump, "\n");
            }
        }
    } else {
        /* 调用点 */
        uint64_t sites[64];
        int n = analysis_find_callsites(fetch_img, &m, main_va, main_end,
                                        plt_va, sites, 64);
        printf("call sites to printf: %d\n", n);
        for (int i = 0; i < n; i++)
            fprintf(dump, "SITE %s %016llx\n", tag,
                    (unsigned long long)sites[i]);

        for (int i = 0; i < n && i < 2; i++) {
            a64_loc_t loc;
            int rc = analysis_locate_first_arg(fetch_img, &m, main_va,
                                               main_end, sites[i], &loc);
            printf("analysis(site %d) rc=%d loc=", i, rc);
            if (rc == 0) {
                if (loc.kind == LOC_REG)
                    printf("REG x%d\n", loc.reg);
                else
                    printf("SLOT [x%d, #%lld] is64=%d\n", loc.base_reg,
                           (long long)loc.off, loc.is64);
                fprintf(dump, "LOC %s site%d %d %d %lld %d\n", tag, i,
                        loc.kind, loc.kind == LOC_REG ? loc.reg : loc.base_reg,
                        (long long)loc.off, loc.is64);
            } else {
                printf("UNKNOWN\n");
            }

            /* 规划 call-guard */
            instr_plan_t plan;
            rc = instr_plan_guard(&m, main_va, main_end, sites[i], 1, 0,
                                  CHECK_ADDR, CALLEE_ADDR, TRAMP_BASE, 0,
                                  &plan);
            printf("plan(site %d) rc=%d patch_len=%d tramp_words=%zu\n", i, rc,
                   plan.patch_len, plan.tramp_words);
            if (rc == INSTR_OK) {
                printf("  patch: ");
                print_hex(plan.patch, (size_t)plan.patch_len);
                printf("\n  orig : ");
                print_hex(plan.orig, (size_t)plan.patch_len);
                printf("\n  tramp:");
                for (size_t k = 0; k < plan.tramp_words; k++)
                    printf(" %08x", plan.tramp[k]);
                printf("\n");
                fprintf(dump, "PLAN %s site%d %016llx %d ",
                        tag, i, (unsigned long long)sites[i], plan.patch_len);
                dump_hex(dump, plan.patch, (size_t)plan.patch_len);
                fprintf(dump, " %zu ", plan.tramp_words);
                for (size_t k = 0; k < plan.tramp_words; k++)
                    fprintf(dump, "%08x", plan.tramp[k]);
                fprintf(dump, "\n");
            }
        }
    }
    free(img);
    return 0;
}

/* ---------------- hook 免疫(磁盘镜像分析)测试 ---------------- */

/*
 * 模拟"先 hook 后分析"场景:Dobby 等框架先改写了函数入口后,
 * 读运行时内存的分析器会读到 hook 跳转而非原始 prologue → NOLOC;
 * 改用磁盘 .so 镜像(原始指令字节)后分析不受任何先行 hook 影响。
 */
static void test_hook_immunity(const char *path) {
    printf("== hook 免疫(磁盘镜像分析)测试 ==\n");
    size_t sz = 0;
    uint8_t *img = read_file(path, &sz);
    if (!img) {
        chk(0, "读取目标文件");
        return;
    }
    elf64_module_t m;
    if (elf64_module_init(&m, (void *)(uintptr_t)RUNTIME_BASE, img, sz) != 0) {
        chk(0, "解析 ELF");
        free(img);
        return;
    }
    uint64_t main_va, main_sz = 0;
    if (elf64_find_symbol(&m, "main", &main_va, &main_sz) != 0) {
        printf("  (skip: 目标中没有 main 符号)\n");
        free(img);
        return;
    }
    uint64_t main_end = find_end(&m, main_va, main_sz);
    uint64_t guard = main_va + 0x40;

    /* 1) 原始镜像:分析成功 */
    a64_loc_t loc;
    int rc = analysis_locate_first_arg(fetch_img, &m, main_va, main_end,
                                       guard, &loc);
    chk(rc == 0, "原始镜像上分析成功");

    /* 2) 模拟 Dobby 先 hook 了入口:复制镜像并把入口改成 ldr/br 绝对跳转 */
    uint8_t *mut = (uint8_t *)malloc(sz);
    if (!mut) {
        chk(0, "分配变异镜像");
        free(img);
        return;
    }
    memcpy(mut, img, sz);
    elf64_module_t mm;
    elf64_module_init(&mm, (void *)(uintptr_t)RUNTIME_BASE, mut, sz);
    {
        uint64_t pc = main_va;
        uint32_t w0 = a64_insn_ldr_lit(16, 1, pc + 8, pc);
        uint32_t w1 = a64_insn_br(16);
        uint64_t q = 0x12345678;
        ptrdiff_t off = elf64_va_to_offset(&mm, pc);
        if (off >= 0 && (size_t)off + 16 <= sz) {
            memcpy(mut + off, &w0, 4);
            memcpy(mut + off + 4, &w1, 4);
            memcpy(mut + off + 8, &q, 8);
        }
    }
    rc = analysis_locate_first_arg(fetch_img, &mm, main_va, main_end,
                                   guard, &loc);
    chk(rc != 0, "入口被 hook 后读内存分析失败(NOLOC,不产生错误补丁)");

    /* 3) 读磁盘镜像 = 原始字节,分析不受 hook 影响 */
    rc = analysis_locate_first_arg(fetch_img, &m, main_va, main_end,
                                   guard, &loc);
    chk(rc == 0, "读磁盘镜像(原始字节)分析不受先行 hook 影响");

    free(mut);
    free(img);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0); /* 崩溃时也能看到输出 */
    if (argc < 3) {
        fprintf(stderr, "usage: test_logic <target.so> <block_target.so> "
                        "<dump_file> [block_symbol=main]\n");
        return 2;
    }
    const char *block_sym = argc > 4 ? argv[4] : "main";
    test_a64_self();
    test_decode_corpus();
    test_analysis_flow();
    test_hook_immunity(argv[2]);

    FILE *dump = fopen(argv[3], "w");
    if (!dump) {
        fprintf(stderr, "cannot open dump file %s\n", argv[3]);
        return 2;
    }
    fprintf(dump, "VER 1\n");
    test_target(argv[1], "call", 0, "main", dump);
    test_target(argv[2], "block", 1, block_sym, dump);
    if (argc > 5)
        test_target(argv[5], "complex", 1, "complex_fn", dump);
    fclose(dump);

    printf("== %s ==\n", g_fail ? "SOME TESTS FAILED" : "ALL HOST LOGIC OK");
    return g_fail ? 1 : 0;
}
