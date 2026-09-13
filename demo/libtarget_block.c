/*
 * libtarget_block.c - 代码块守卫的演示目标
 *
 * 用两条内联汇编"标记"夹住被守卫的代码块:
 *   mov x9, #0x6d0   -> 块起始标记
 *   mov x9, #0x6d1   -> 块结束标记
 *
 * demo_main 扫描 main 找到这两个标记,得出 [block_start, block_end),
 * 然后调用 instr_guard_block 包裹:
 *   if (mycheck(argc)) { <块> }        (mycheck 拒绝时整块跳过)
 *
 * 必须用 -O0 编译,保证 asm volatile 顺序不被重排。
 */
#include <stdio.h>

__attribute__((visibility("default")))
int main(int argc) {
    int sum = 0;

    /* 守卫点之前的"其他逻辑" */
    for (int k = 1; k < argc; k++)
        sum += k;

    asm volatile("mov x9, #0x6d0"); /* 块起始标记 */

    /* ================= 被守卫的代码块 ================= */
    for (int k = 0; k < argc; k++)
        sum += k * 3;
    printf("block executed: sum=%d argc=%d\n", sum, argc);
    /* ================= 块结束 ================= */

    asm volatile("mov x9, #0x6d1"); /* 块结束标记 */

    return sum;
}
