/*
 * libtarget_cpp.cpp - 实例方法(C++ 成员函数)守卫演示目标
 *
 * 用 instr_guard_block_va_args 守卫 Foo::work 内的代码块:
 *   check 收到入口参数 x0~x7:a0 = this,a1 = n(与 dobby 替换函数一致)。
 */
#include <stdio.h>

class Foo {
public:
    int base; /* 偏移 0 */
    __attribute__((visibility("default"))) int work(int n);
};

int Foo::work(int n) {
    int t = base + n;

    asm volatile("mov x9, #0x6d0"); /* 块起始标记 */

    /* ================= 被守卫的代码块 ================= */
    t = t * 3 + 1;
    printf("work ran: t=%d this=%p\n", t, (void *)this);
    /* ================= 块结束 ================= */

    asm volatile("mov x9, #0x6d1"); /* 块结束标记 */

    return t;
}

/* 供演示程序 dlsym 调用的入口(导出符号名: _ZN3Foo4workEi) */
extern "C" __attribute__((visibility("default")))
void libtarget_cpp_dummy(void) {}
