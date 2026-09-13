/*
 * libcheck.c - 真实编译的检查函数(验证 check 只需声明目标函数实际参数个数)
 *
 * mycheck2 只声明 2 个参数(a0=this, a1=n),trampoline 会传 8 个寄存器参数,
 * 多余的被忽略 —— 验证 AAPCS64 下"少声明"完全安全。
 */
#include <stdint.h>

__attribute__((visibility("default")))
int mycheck2(int64_t a0, int64_t a1) {
    return (int)(a1 != 0); /* n==0 拒绝 */
}

__attribute__((visibility("default")))
int mycheck1(int64_t a0) {
    return (int)(a0 != 0); /* argc==0 拒绝 */
}
