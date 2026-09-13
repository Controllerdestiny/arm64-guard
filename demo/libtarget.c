/*
 * libtarget.c - 调用点守卫的演示目标
 *
 * 编译:-O0 与 -O2 两个版本,验证分析器对"参数存活位置"的两种结果:
 *   -O0(带帧指针):argc 压栈到 [x29, #off]
 *   -O2(寄存器分配):argc 保存在 callee-saved 寄存器(如 w19)
 *
 * 用 instr_guard_callsites 守卫后:
 *   main(0) -> mycheck 拒绝 -> printf 被跳过
 *   main(n>0) -> printf 正常执行
 */
#include <stdio.h>

__attribute__((visibility("default")))
int main(int argc) {
    /* 守卫点之前的"其他逻辑" */
    volatile int pre = argc * 2;

    printf("target printf called: argc=%d pre=%d\n", argc, pre);

    return argc + pre;
}
