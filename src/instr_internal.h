/*
 * instr_internal.h - 插桩引擎内部接口
 *
 * instr_plan.c 只做"规划"(纯逻辑,无任何系统调用):
 *   分析参数位置 -> 重定位被搬移指令 -> 生成 trampoline 字节 -> 生成补丁字节
 * instr.c 做"应用"(mprotect / mmap / cache flush / 卸载登记)。
 * 这样宿主机可以不经 ARM64 直接单测规划部分。
 */
#ifndef INSTR_INTERNAL_H
#define INSTR_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "instr.h"
#include "elf64.h"
#include "analysis.h"

#ifdef __cplusplus
extern "C" {
#endif

#define INSTR_PATCH_LEN   12   /* 形态 A 补丁长度                          */
#define INSTR_PATCH_MAX   16   /* 形态 B 补丁长度(缓冲上限)                */
#define INSTR_TRAMP_MAX   192  /* trampoline 最大指令字(含字面量池)        */

typedef struct {
    uint64_t addr;           /* 守卫点地址(补丁首地址)                     */
    uint8_t patch[INSTR_PATCH_MAX];
    uint8_t orig[INSTR_PATCH_MAX];
    int patch_len;           /* 实际补丁长度:12(形态A) 或 16(形态B)        */
    uint32_t tramp[INSTR_TRAMP_MAX];
    size_t tramp_words;
    int is_call_guard;
    uint64_t block_end;      /* block-guard 的块尾(call-guard 为 0)        */
} instr_plan_t;

/*
 * 规划一次守卫:
 *   m          已解析的模块(基址 + 节表)
 *   caller_start / caller_end  caller 的指令范围(运行时地址)
 *   guard_pc   守卫点(补丁首地址;call-guard 为 bl 指令地址)
 *   is_call_guard 1=守卫单条调用(call-guard),0=守卫代码块(block-guard)
 *   block_end  block-guard 的块尾(跳过目标);call-guard 传 0
 *   check_addr mycheck 的运行时地址
 *   callee_addr call-guard 用:被调函数的运行时地址(已解析)
 *   tramp_base trampoline 将放置的运行时地址(用于重定位被搬移指令)
 *   out        输出补丁与 trampoline 字节
 * 返回 0 成功;负错误码见 instr.h。
 */
int instr_plan_guard(const elf64_module_t *m,
                     uint64_t caller_start, uint64_t caller_end,
                     uint64_t guard_pc, int is_call_guard,
                     uint64_t block_end, uint64_t check_addr,
                     uint64_t callee_addr, uint64_t tramp_base,
                     instr_plan_t *out);

#ifdef __cplusplus
}
#endif

#endif /* INSTR_INTERNAL_H */
