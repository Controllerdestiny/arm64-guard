/*
 * dump_guard.c —— 在设备上对真实 libil2cpp.so 生成 Player.Update 两个块的
 * 守卫规划(补丁 + trampoline),输出 hex 供 llvm-objdump 反汇编检查 pass 路径。
 *
 * 用法: dump_guard <libil2cpp.so路径>
 * 输出: ./guard_dump.txt
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "elf64.h"
#include "analysis.h"
#include "instr_internal.h"

#define UPDATE_RVA    0x13ABBFC
#define PHYS_START    0x13B5EF8
#define PHYS_END      0x13B6968
#define LIQ_START     0x13B69F0
#define LIQ_END       0x13B6BEC

static void dump_hex(FILE* f, const uint8_t* p, int n) {
    for (int i = 0; i < n; i++)
        fprintf(f, "%02x", p[i]);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <libil2cpp.so>\n", argv[0]);
        return 1;
    }
    void* h = dlopen(argv[1], RTLD_NOW);
    if (!h) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }
    /* 用 /proc/self/maps 拿 libil2cpp.so 的 r-xp 基址 */
    FILE* mf = fopen("/proc/self/maps", "r");
    char line[512];
    uint64_t libbase = 0;
    while (mf && fgets(line, sizeof(line), mf)) {
        if (strstr(line, "/libil2cpp.so") && strstr(line, "r-xp")) {
            unsigned long a;
            sscanf(line, "%lx-", &a);
            libbase = (uint64_t)a;
            break;
        }
    }
    if (mf) fclose(mf);
    if (!libbase) {
        fprintf(stderr, "libil2cpp base not found in maps\n");
        return 1;
    }
    fprintf(stderr, "libil2cpp base = 0x%llx\n", (unsigned long long)libbase);

    elf64_module_t m;
    if (elf64_module_init(&m, (const void*)(uintptr_t)libbase, NULL, 0) != 0) {
        fprintf(stderr, "elf64_module_init failed\n");
        return 1;
    }
    fprintf(stderr, "module size = 0x%zx\n", m.size);

    FILE* out = fopen("/data/local/tmp/guard_dump.txt", "w");
    if (!out) { fprintf(stderr, "can't open output\n"); return 1; }

    uint64_t fn = libbase + UPDATE_RVA;
    uint64_t cend = fn + 0x40000; /* 粗略函数上界(仅规划用) */

    /* ---- 物理块:数据流模式(与旧 block 模式一致) ---- */
    {
        instr_plan_t plan;
        int rc = instr_plan_guard(&m, fn, cend, libbase + PHYS_START, 0,
                                  libbase + PHYS_END, 0x6000001000ull, 0,
                                  libbase + 0x2000000, 0, &plan);
        fprintf(out, "PHYS block rc=%d plen=%d tramp_words=%zu fix=%d\n", rc,
                plan.patch_len, plan.tramp_words, plan.fix_count);
        if (rc == 0) {
            fprintf(out, "PATCH ");
            dump_hex(out, plan.patch, plan.patch_len);
            fprintf(out, "\nTRAMP ");
            for (size_t i = 0; i < plan.tramp_words; i++)
                fprintf(out, "%08x", plan.tramp[i]);
            fprintf(out, "\n");
            for (int i = 0; i < plan.fix_count; i++)
                fprintf(out, "FIX %llx: %08x -> %08x\n",
                        (unsigned long long)plan.fixes[i].addr,
                        plan.fixes[i].orig_insn, plan.fixes[i].new_insn);
        }
    }

    /* ---- 物理块:快照模式 ---- */
    {
        instr_plan_t plan, ep;
        int rc = instr_plan_entry_snapshot(&m, fn, libbase + PHYS_END,
                                           libbase + 0x2000000 + 0x1200,
                                           libbase + 0x2000000 + 0x1000,
                                           0, 0, &ep);
        fprintf(out, "PHYS entry-snap rc=%d plen=%d tramp_words=%zu\n", rc,
                ep.patch_len, ep.tramp_words);
        if (rc == 0) {
            fprintf(out, "EPATCH ");
            dump_hex(out, ep.patch, ep.patch_len);
            fprintf(out, "\nETRAMP ");
            for (size_t i = 0; i < ep.tramp_words; i++)
                fprintf(out, "%08x", ep.tramp[i]);
            fprintf(out, "\n");
        }
        rc = instr_plan_guard(&m, fn, cend, libbase + PHYS_START, 0,
                              libbase + PHYS_END, 0x6000001000ull, 0,
                              libbase + 0x2000000,
                              libbase + 0x2000000 + 0x1200, &plan);
        fprintf(out, "PHYS snap-block rc=%d plen=%d tramp_words=%zu fix=%d\n",
                rc, plan.patch_len, plan.tramp_words, plan.fix_count);
        if (rc == 0) {
            fprintf(out, "PATCH2 ");
            dump_hex(out, plan.patch, plan.patch_len);
            fprintf(out, "\nTRAMP2 ");
            for (size_t i = 0; i < plan.tramp_words; i++)
                fprintf(out, "%08x", plan.tramp[i]);
            fprintf(out, "\n");
            for (int i = 0; i < plan.fix_count; i++)
                fprintf(out, "FIX2 %llx: %08x -> %08x\n",
                        (unsigned long long)plan.fixes[i].addr,
                        plan.fixes[i].orig_insn, plan.fixes[i].new_insn);
        }
    }

    /* ---- 液体块:快照模式 ---- */
    {
        instr_plan_t plan;
        int rc = instr_plan_guard(&m, fn, cend, libbase + LIQ_START, 0,
                                  libbase + LIQ_END, 0x6000001000ull, 0,
                                  libbase + 0x2000000,
                                  libbase + 0x2000000 + 0x1200, &plan);
        fprintf(out, "LIQ snap-block rc=%d plen=%d tramp_words=%zu fix=%d\n",
                rc, plan.patch_len, plan.tramp_words, plan.fix_count);
        if (rc == 0) {
            fprintf(out, "PATCH3 ");
            dump_hex(out, plan.patch, plan.patch_len);
            fprintf(out, "\nTRAMP3 ");
            for (size_t i = 0; i < plan.tramp_words; i++)
                fprintf(out, "%08x", plan.tramp[i]);
            fprintf(out, "\n");
            for (int i = 0; i < plan.fix_count; i++)
                fprintf(out, "FIX3 %llx: %08x -> %08x\n",
                        (unsigned long long)plan.fixes[i].addr,
                        plan.fixes[i].orig_insn, plan.fixes[i].new_insn);
        }
    }

    fclose(out);
    fprintf(stderr, "dumped to /data/local/tmp/guard_dump.txt\n");
    return 0;
}
