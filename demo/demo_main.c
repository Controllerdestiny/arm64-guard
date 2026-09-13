/*
 * demo_main.c - 演示程序(dobby 式极简 API)
 *
 * 用法:
 *   demo_main block [libtarget_block.so]   # 守卫 main 里标记之间的代码块
 *   demo_main cpp   [libtarget_cpp.so]     # 守卫 C++ 实例方法 Foo::work 内的代码块
 *
 * 行为(拒绝条件):
 *   block 模式:a0(=argc) == 0 时拒绝 -> main(0) 的代码块被跳过
 *   cpp 模式:  a1(=n) == 0 时拒绝    -> work(0) 的代码块被跳过
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "instr.h"

/* 块标记常量(与 libtarget_block.c / libtarget_cpp.cpp 一致) */
#define MARK_START 0x6d0
#define MARK_END   0x6d1

/* movz x9, #imm 的编码检测:0xD2800000 | (imm<<5) | 9 */
static int is_marker(uint32_t w, int *imm) {
    if ((w & 0xFFE0001Fu) == (0xD2800000u | 9)) {
        *imm = (int)((w >> 5) & 0xFFFF);
        return 1;
    }
    return 0;
}

/* 扫描 fn 找 [start_marker, end_marker),返回块范围(不含标记) */
static int find_block(uintptr_t fn, uint64_t *bstart, uint64_t *bend) {
    int seen_start = 0;
    for (uintptr_t pc = fn; pc < fn + (1u << 20) * 4; pc += 4) {
        uint32_t w;
        memcpy(&w, (void *)pc, 4);
        int imm = 0;
        if (!is_marker(w, &imm))
            continue;
        if (imm == MARK_START && !seen_start) {
            *bstart = pc + 4;
            seen_start = 1;
        } else if (imm == MARK_END && seen_start) {
            *bend = pc;
            return 0;
        }
    }
    return -1;
}

/* block 模式检查:a0 = argc */
static int check_argc(int64_t a0, int64_t a1, int64_t a2, int64_t a3,
                      int64_t a4, int64_t a5, int64_t a6, int64_t a7) {
    int allow = (a0 != 0);
    fprintf(stderr, "mycheck(argc=%lld) -> %s\n", (long long)a0,
            allow ? "ALLOW" : "DENY");
    return allow;
}

/* cpp 模式检查:a0 = this,a1 = n */
static int check_n(int64_t a0, int64_t a1, int64_t a2, int64_t a3,
                   int64_t a4, int64_t a5, int64_t a6, int64_t a7) {
    int allow = (a1 != 0);
    fprintf(stderr, "mycheck(this=%p, n=%lld) -> %s\n", (void *)(uintptr_t)a0,
            (long long)a1, allow ? "ALLOW" : "DENY");
    return allow;
}

static void run_case(const char *label, void *fn, intptr_t a0, intptr_t a1) {
    intptr_t r;
    if (a1 == (intptr_t)-1) { /* block 模式:int(*)(int) */
        int (*f)(int) = (int (*)(int))fn;
        r = f((int)a0);
    } else { /* cpp 模式:int(*)(void*, int) */
        int (*f)(void *, int) = (int (*)(void *, int))fn;
        r = f((void *)a0, (int)a1);
    }
    printf("  ret=%ld\n", (long)r);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "block";
    const char *path = argc > 2 ? argv[2]
                                : (strcmp(mode, "cpp") == 0
                                       ? "libtarget_cpp.so"
                                       : "libtarget_block.so");
    const char *sym = (strcmp(mode, "cpp") == 0) ? "_ZN3Foo4workEi" : "main";

    void *h = dlopen(path, RTLD_NOW);
    if (!h) {
        fprintf(stderr, "dlopen(%s) failed: %s\n", path, dlerror());
        return 1;
    }
    void *fn = dlsym(h, sym);
    if (!fn) {
        fprintf(stderr, "dlsym(%s) failed\n", sym);
        return 1;
    }

    uint64_t bstart, bend;
    if (find_block((uintptr_t)fn, &bstart, &bend) != 0) {
        fprintf(stderr, "block markers not found\n");
        return 1;
    }
    printf("== %s 守卫 [%p, %p) in %s ==\n", mode, (void *)(uintptr_t)bstart,
           (void *)(uintptr_t)bend, path);

    void *check = (strcmp(mode, "cpp") == 0) ? (void *)check_n
                                             : (void *)check_argc;
    int rc = instr_guard_block(fn, (void *)(uintptr_t)bstart,
                               (void *)(uintptr_t)bend, check);
    if (rc != INSTR_OK) {
        fprintf(stderr, "instr_guard_block failed: %s\n", instr_last_error());
        return 1;
    }
    printf("guard installed OK\n");

    if (strcmp(mode, "cpp") == 0) {
        printf("== work(0) ==\n"); /* 拒绝 -> 块跳过 */
        run_case("cpp", fn, 0, 0);
        printf("== work(2) ==\n"); /* 放行 -> 块执行 */
        run_case("cpp", fn, 0, 2);
        printf("== work(3) ==\n");
        run_case("cpp", fn, 0, 3);
    } else {
        printf("== main(0) ==\n"); /* 拒绝 -> 块跳过 */
        run_case("block", fn, 0, -1);
        printf("== main(2) ==\n"); /* 放行 */
        run_case("block", fn, 2, -1);
        printf("== main(5) ==\n");
        run_case("block", fn, 5, -1);
    }
    return 0;
}
