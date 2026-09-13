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

/* ---------------- a64 自检 ---------------- */

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
                              CHECK_ADDR, 0, TRAMP_BASE, &plan);
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
                                  CHECK_ADDR, CALLEE_ADDR, TRAMP_BASE, &plan);
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

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0); /* 崩溃时也能看到输出 */
    if (argc < 3) {
        fprintf(stderr, "usage: test_logic <target.so> <block_target.so> "
                        "<dump_file> [block_symbol=main]\n");
        return 2;
    }
    const char *block_sym = argc > 4 ? argv[4] : "main";
    test_a64_self();

    FILE *dump = fopen(argv[3], "w");
    if (!dump) {
        fprintf(stderr, "cannot open dump file %s\n", argv[3]);
        return 2;
    }
    fprintf(dump, "VER 1\n");
    test_target(argv[1], "call", 0, "main", dump);
    test_target(argv[2], "block", 1, block_sym, dump);
    fclose(dump);

    printf("== %s ==\n", g_fail ? "SOME TESTS FAILED" : "ALL HOST LOGIC OK");
    return g_fail ? 1 : 0;
}
