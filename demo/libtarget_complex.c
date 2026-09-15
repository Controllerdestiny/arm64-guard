/*
 * libtarget_complex.c - 复杂函数守卫演示目标
 *
 * 8 个入口参数 + 5KB 大栈帧(帧偏移 > 4096)+ 全部参数先压栈:
 * 覆盖"复杂函数"的参数恢复场景:
 *   - 8 参数(arg0..arg7)必须全部被数据流分析恢复并传给 check;
 *   - 大栈帧:部分栈槽偏移超过 4096,考验发射器的任意偏移加载;
 *   - 块内包含调用(printf)与循环。
 *
 * 用 mov x9, #0x6d0 / #0x6d1 标记夹住代码块(与其它 demo 目标一致)。
 * 必须用 -O0 编译。
 */
#include <stdio.h>

__attribute__((visibility("default")))
long complex_fn(long a0, long a1, long a2, long a3,
                long a4, long a5, long a6, long a7) {
    volatile long slots[8];
    volatile char big[5000];   /* 大栈帧:sp 偏移超过 4096 */
    long t = 0;

    /* 守卫点之前的"其他逻辑":全部参数压栈(volatile 强制落栈) */
    slots[0] = a0;
    slots[1] = a1;
    slots[2] = a2;
    slots[3] = a3;
    slots[4] = a4;
    slots[5] = a5;
    slots[6] = a6;
    slots[7] = a7;
    t = a0 ^ a7;

    asm volatile("mov x9, #0x6d0" ::: "x9"); /* 块起始标记 */

    /* ================= 被守卫的代码块 ================= */
    for (int i = 0; i < 8; i++) {
        big[i * 16] = (char)(slots[i] & 0xff);
        t += slots[i];
    }
    printf("complex ran: t=%ld\n", t);
    /* ================= 块结束 ================= */

    asm volatile("mov x9, #0x6d1" ::: "x9"); /* 块结束标记 */

    return t + slots[7] + big[0];
}
