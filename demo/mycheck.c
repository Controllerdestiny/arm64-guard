/*
 * mycheck.c - 守卫检查函数示例
 *
 * 按目标函数"入口"的 x0~x7 收到其参数,只需声明目标函数实际有的参数个数:
 *   普通函数      a0 = 第一个参数(argc)
 *   C++ 实例方法 a0 = this,a1 = 第一个显式参数
 * 这里目标函数是 int main(int argc),所以只声明 1 个参数。
 * 返回 0 拒绝(argc 为 0 跳过),非 0 放行。
 */
#include <stdio.h>

#if defined(__ANDROID__)
#include <android/log.h>
#define MYLOG(...) \
    __android_log_print(ANDROID_LOG_INFO, "instr", __VA_ARGS__)
#else
#define MYLOG(...) fprintf(stderr, __VA_ARGS__)
#endif

__attribute__((visibility("default")))
int mycheck(int64_t a0) {
    int allow = (a0 != 0);
    MYLOG("mycheck(argc=%lld) -> %s\n", (long long)a0,
          allow ? "ALLOW" : "DENY");
    return allow;
}
