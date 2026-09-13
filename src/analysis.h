/*
 * analysis.h - 参数存活位置数据流分析
 *
 * 目标:在 caller 函数范围内,确定其入口第一个参数(w0/x0)在
 * 某个守卫点(guard_pc)处的存活位置 —— 它可能仍在某个寄存器里,
 * 也可能已被压栈到 [x29/xsp, #off]。
 */
#ifndef ANALYSIS_H
#define ANALYSIS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 跟踪的入口参数个数(x0~x7) */
#define ANALYSIS_NARGS 8

typedef enum {
    LOC_UNKNOWN = 0,   /* 未能确定 */
    LOC_REG,           /* 寄存器 reg */
    LOC_SLOT,          /* 栈槽 [base_reg, #off](base 31 = sp) */
} a64_loc_kind_t;

typedef struct {
    a64_loc_kind_t kind;
    int reg;           /* LOC_REG:寄存器编号 0-30 */
    int base_reg;      /* LOC_SLOT:29 = x29, 31 = sp */
    int64_t off;       /* LOC_SLOT:字节偏移 */
    int is64;          /* 槽位宽度(32/64),决定 ldr w/x */
} a64_loc_t;

/* 取指令回调:返回 addr 处的 32 位指令字 */
typedef uint32_t (*a64_fetch_fn)(void *ctx, uint64_t addr);

/*
 * 分析 [start, end) 内,guard_pc 处(执行前)入口参数 w0 的存活位置。
 * 返回 0 成功;负值表示无法确定(守卫点不可达 / 位置未知)。
 */
int analysis_locate_first_arg(a64_fetch_fn fetch, void *ctx,
                              uint64_t start, uint64_t end,
                              uint64_t guard_pc, a64_loc_t *out);

/*
 * 分析入口 x0~x7 共 8 个参数在守卫点处的存活位置(多参数 / 实例方法用)。
 * locs 填 8 项(LOC_UNKNOWN = 不可恢复,调用方传 0 即可);
 * *nfound 返回可恢复个数。返回 0 成功。
 */
int analysis_locate_args(a64_fetch_fn fetch, void *ctx,
                         uint64_t start, uint64_t end,
                         uint64_t guard_pc, a64_loc_t *locs, int *nfound);

/*
 * 枚举 [start, end) 内所有 `bl <callee_va>` 调用点。
 * 返回个数;out 最多 max 个。
 */
int analysis_find_callsites(a64_fetch_fn fetch, void *ctx,
                            uint64_t start, uint64_t end,
                            uint64_t callee_va, uint64_t *out, int max);

#ifdef __cplusplus
}
#endif

#endif /* ANALYSIS_H */
