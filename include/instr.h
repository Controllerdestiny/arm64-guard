/*
 * instr.h - arm64-guard:AArch64 运行时插桩(唯一头文件,dobby 式极简用法)
 *
 * 一行调用,把目标函数里的代码块变成条件执行:
 *
 *     int (*fn)(...) { ... <代码块> ... }
 *     =>
 *     int (*fn)(...) { ... if (check(this, arg1, ...)) { <代码块> } ... }
 *
 * 用法:
 *
 *     #include "instr.h"
 *
 *     // 检查函数:按目标函数"入口"的 x0~x7 收到其参数,
 *     // 只需声明目标函数实际有的参数个数(多的寄存器参数自动忽略)。
 *     //   普通函数      a0 = 第一个参数
 *     //   C++ 实例方法 a0 = this,a1 = 第一个显式参数
 *     // 返回 0 跳过,非 0 放行。
 *     int mycheck(int64_t a0, int64_t a1) {   // 例:目标 Foo::work(int n)
 *         return a1 != 0;
 *     }
 *
 *     instr_guard_block(fn_addr, block_start, block_end, (void *)mycheck);
 *
 * fn_addr 可以是 dlsym / vtable / 偏移得到的任意函数地址(自动 dladdr 定位模块,
 * 无需句柄与符号表)。支持很大的函数(上限 1M 条指令)。
 */
#ifndef INSTR_H
#define INSTR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 错误码 */
enum {
    INSTR_OK = 0,
    INSTR_ERR_ARG,        /* 参数非法(NULL、范围错误)                     */
    INSTR_ERR_NOT_ELF,    /* 函数地址所在模块不是可解析的 AArch64 ELF      */
    INSTR_ERR_NOLOC,      /* 无法分析出入参位置(见 README 限制)            */
    INSTR_ERR_MPROTECT,   /* mprotect 失败(Android 上常是 SELinux execmem) */
    INSTR_ERR_MMAP,       /* mmap trampoline 失败                          */
    INSTR_ERR_RELOC,      /* 被搬移指令暂不支持重定位                       */
    INSTR_ERR_RANGE,      /* 块范围非法:end-start < 12 或越界               */
    INSTR_ERR_UNALIGNED,  /* 地址未 4 字节对齐                             */
    INSTR_ERR_NOTPATCHED, /* instr_unpatch:该地址未被本库修补              */
    INSTR_ERR_ENTRY_BUSY, /* 入口快照模式:函数入口已被其它 hook 占用        */
    INSTR_ERR_OTHER
};

/* 最近一次错误的描述字符串 */
const char *instr_last_error(void);

/*
 * 守卫 fn 内 [block_start, block_end) 的代码块:
 *     if (check(入口参数...)) { <代码块> }       否则整块跳过
 *
 * check:任意签名的函数指针(传 (void*)check 即可)。调用时按 AArch64 调用约定
 * 把目标函数"入口"的 x0~x7 传给它(自动数据流恢复,无法恢复的为 0):
 *     C++ 实例方法  ->  x0 = this,x1 = 第一个显式参数,...
 *     普通函数      ->  x0 = 第一个参数,x1 = 第二个参数,...
 * 因此 check **只需声明目标函数实际有的参数个数**(最多 8 个,多余的寄存器
 * 参数被忽略)。返回 0 跳过目标代码,非 0 放行。
 *
 * fn:目标函数地址(自动 dladdr 定位所在模块,无需句柄);
 * block_end - block_start >= 12 字节。
 * 返回 INSTR_OK 或错误码。
 */
int instr_guard_block(void *fn, void *block_start, void *block_end,
                      void *check);

/*
 * 入口快照模式(可选,dobby 级万能):与 instr_guard_block 相同,
 * 但额外在 fn 入口打一个 16 字节快照补丁,把入口的 x0~x7 原样存入专用
 * 快照区;守卫点的 check **100% 收到函数入口的 x0~x7** —— 与函数内部把
 * 参数搬到哪里、指令多复杂、数据流是否可分析完全无关。
 *
 * 代价:fn 入口被修改(入口 16 字节搬到 trampoline,指令级等价),且每次
 * 调用该函数都会多执行一次保存/恢复;要求 block_start >= fn + 16。
 * 限制:守卫点到达前若同一函数被递归/自调用重新进入,快照会被内层覆盖
 * (罕见;普通单层调用不受影响)。同一函数只支持安装一个快照守卫。
 */
int instr_guard_block_snap(void *fn, void *block_start, void *block_end,
                           void *check);

/* 卸载:把原指令写回、释放 trampoline。传 block_start。 */
int instr_unpatch(void *patched_addr);

#ifdef __cplusplus
}
#endif

#endif /* INSTR_H */
