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
#define INSTR_TRAMP_MAX   256  /* trampoline 最大指令字(含字面量池)        */
#define INSTR_FIX_MAX     64   /* 外部回跳补丁区的分支重映射上限            */

/* 外部分支修复项:函数内某条分支的目标原本落在补丁区内,将其目标重映射。 */
typedef struct {
    uint64_t addr;          /* 需要改写的分支指令地址                    */
    uint32_t orig_insn;     /* 原始指令(卸载时恢复)                      */
    uint32_t new_insn;      /* 改写后的指令(目标已重映射)                */
} instr_fix_t;

/* 被搬移指令映射:原地址 -> trampoline 新地址(供外部回跳精确重映射) */
typedef struct {
    uint64_t old_pc;
    uint64_t new_addr;
} instr_disp_t;

typedef struct {
    uint64_t addr;           /* 守卫点地址(补丁首地址)                     */
    uint8_t patch[INSTR_PATCH_MAX];
    uint8_t orig[INSTR_PATCH_MAX];
    int patch_len;           /* 实际补丁长度:12(形态A) 或 16(形态B)        */
    uint32_t tramp[INSTR_TRAMP_MAX];
    size_t tramp_words;
    int is_call_guard;
    uint64_t block_end;      /* block-guard 的块尾(call-guard 为 0)        */
    uint64_t snap_addr;      /* 入口快照区地址(0 = 数据流分析模式)         */
    instr_disp_t disp[8];    /* 被搬移指令 原地址->trampoline 新地址        */
    int disp_count;
    instr_fix_t fixes[INSTR_FIX_MAX]; /* 外部回跳补丁区的分支重映射        */
    int fix_count;
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
                     uint64_t snap_addr, instr_plan_t *out);

/*
 * 规划函数入口的"参数快照"补丁(入口快照模式):
 *   fn 入口被改写为 16 字节跳转到 entry_tramp_base 处的入口 trampoline,
 *   入口 trampoline 把 x0~x7 保存到 snap_addr,重放入口被覆盖的指令,
 *   再跳回 fn+16。之后任何守卫点都能从 snap_addr 读到入口参数(100% 可恢复,
 *   与函数内部复杂度无关,类似 dobby 的入口 hook)。
 * block_end 用于外部回跳修复的扫描范围。返回 0 成功。
 */
int instr_plan_entry_snapshot(const elf64_module_t *m,
                              uint64_t fn, uint64_t block_end,
                              uint64_t snap_addr, uint64_t entry_tramp_base,
                              instr_plan_t *out);

#ifdef __cplusplus
}
#endif

#endif /* INSTR_INTERNAL_H */
