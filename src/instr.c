/*
 * instr.c - 运行时插桩引擎(应用层)
 *
 * 职责:解析模块 -> 定位 caller -> 规划补丁(instr_plan.c)
 *      -> mmap trampoline -> mprotect 改写调用点 -> 登记/卸载。
 * Android / Linux aarch64。
 */
#include "instr.h"
#include "instr_internal.h"
#include "a64.h"
#include "elf64.h"
#include "analysis.h"

#include <sys/mman.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#define TRAMP_PAGE 4096
#define MAX_RECS   64

static char g_err[256];

const char *instr_last_error(void) {
    return g_err;
}

static void set_err(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_err, sizeof(g_err), fmt, ap);
    va_end(ap);
}

/* ---------------- 补丁登记表 ---------------- */

typedef struct {
    uint64_t addr;
    uint8_t orig[16];
    int len;
    uint8_t *tramp;
    size_t tsz;
    int used;
} rec_t;

static rec_t g_recs[MAX_RECS];

static int patch_register(uint64_t addr, const uint8_t *orig, int len,
                          uint8_t *tramp, size_t tsz) {
    for (int i = 0; i < MAX_RECS; i++) {
        if (!g_recs[i].used) {
            g_recs[i].addr = addr;
            memcpy(g_recs[i].orig, orig, (size_t)len);
            g_recs[i].len = len;
            g_recs[i].tramp = tramp;
            g_recs[i].tsz = tsz;
            g_recs[i].used = 1;
            return INSTR_OK;
        }
    }
    set_err("patch table full (%d entries)", MAX_RECS);
    return INSTR_ERR_OTHER;
}

/* ---------------- 内存操作 ---------------- */

static int apply_bytes(void *addr, const uint8_t *bytes, size_t len) {
    long psz = sysconf(_SC_PAGESIZE);
    if (psz <= 0)
        psz = 4096;
    uintptr_t p = (uintptr_t)addr & ~(uintptr_t)(psz - 1);
    size_t span = ((uintptr_t)addr + len - p + (uintptr_t)psz - 1) &
                  ~(uintptr_t)(psz - 1);
    if (mprotect((void *)p, span, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        set_err("mprotect(%p, %zu, RWX) failed (SELinux execmem?)", (void *)p,
                span);
        return INSTR_ERR_MPROTECT;
    }
    memcpy(addr, bytes, len);
    __builtin___clear_cache((char *)addr, (char *)addr + (long)len);
    return INSTR_OK;
}

static uint32_t fetch_runtime(void *ctx, uint64_t addr) {
    const elf64_module_t *m = (const elf64_module_t *)ctx;
    ptrdiff_t off = elf64_va_to_offset(m, addr);
    if (off < 0)
        return 0;
    if (m->size && (size_t)off + 4 > m->size)
        return 0;
    const uint8_t *img = m->image ? m->image : m->base;
    uint32_t w;
    memcpy(&w, img + off, 4);
    return w;
}

/* ---------------- 规划并应用一次守卫 ---------------- */

static int apply_plan(const elf64_module_t *m, uint64_t cstart, uint64_t cend,
                      uint64_t guard, int is_call_guard, uint64_t block_end,
                      uint64_t check, uint64_t callee) {
    instr_plan_t plan;
    int rc = instr_plan_guard(m, cstart, cend, guard, is_call_guard,
                              block_end, check, callee, 0, &plan);
    if (rc != INSTR_OK) {
        set_err("plan failed: %d at guard %p", rc, (void *)(uintptr_t)guard);
        return rc;
    }
    if (plan.tramp_words == 0) {
        set_err("empty trampoline");
        return INSTR_ERR_OTHER;
    }

    uint8_t *tramp = mmap(NULL, TRAMP_PAGE, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (tramp == MAP_FAILED) {
        set_err("mmap trampoline failed");
        return INSTR_ERR_MMAP;
    }

    /* 以真实基址重新规划(被搬移的 PC 相对指令需要真实地址) */
    rc = instr_plan_guard(m, cstart, cend, guard, is_call_guard, block_end,
                          check, callee, (uint64_t)(uintptr_t)tramp, &plan);
    if (rc != INSTR_OK) {
        set_err("re-plan failed: %d", rc);
        munmap(tramp, TRAMP_PAGE);
        return rc;
    }
    size_t tsz = plan.tramp_words * 4;
    memcpy(tramp, plan.tramp, tsz);
    __builtin___clear_cache((char *)tramp, (char *)tramp + (long)tsz);

    rc = apply_bytes((void *)(uintptr_t)guard, plan.patch, plan.patch_len);
    if (rc != INSTR_OK) {
        munmap(tramp, TRAMP_PAGE);
        return rc;
    }
    return patch_register(guard, plan.orig, plan.patch_len, tramp, TRAMP_PAGE);
}

/* ---------------- 公共 API ---------------- */

/* 无符号大小:扫到最后一个 ret(上限 1M 条指令 = 4MB,支持很大的函数) */
static uint64_t scan_fn_end(const elf64_module_t *m, uint64_t va) {
    uint64_t last = va + 4;
    for (uint64_t pc = va; pc < va + (1u << 20) * 4; pc += 4) {
        uint32_t w = fetch_runtime((void *)m, pc);
        if (!w)
            break;
        a64_insn_t d;
        a64_decode(pc, w, &d);
        if (d.kind == A64_RET)
            last = pc + 4;
    }
    return last;
}

int instr_guard_block(void *fn, void *block_start, void *block_end,
                      void *check) {
    if (!fn || !block_start || !block_end || !check) {
        set_err("invalid argument");
        return INSTR_ERR_ARG;
    }
    /* 从函数地址自动定位所在模块(无需句柄/符号名,dobby 式用法) */
    Dl_info info;
    if (!dladdr(fn, &info) || !info.dli_fbase) {
        set_err("dladdr(%p) failed: address not in a loaded module", fn);
        return INSTR_ERR_ARG;
    }
    elf64_module_t m;
    if (elf64_module_init(&m, info.dli_fbase, NULL, 0) != 0) {
        set_err("module at %p is not an AArch64 ELF", info.dli_fbase);
        return INSTR_ERR_NOT_ELF;
    }
    uint64_t cstart = (uint64_t)(uintptr_t)fn;
    uint64_t cend = scan_fn_end(&m, cstart); /* 支持很大的函数 */
    return apply_plan(&m, cstart, cend, (uint64_t)(uintptr_t)block_start, 0,
                      (uint64_t)(uintptr_t)block_end,
                      (uint64_t)(uintptr_t)check, 0);
}

int instr_unpatch(void *patched_addr) {
    uint64_t a = (uint64_t)(uintptr_t)patched_addr;
    for (int i = 0; i < MAX_RECS; i++) {
        if (g_recs[i].used && g_recs[i].addr == a) {
            int rc = apply_bytes((void *)(uintptr_t)a, g_recs[i].orig,
                                 (size_t)g_recs[i].len);
            if (rc != INSTR_OK)
                return rc;
            munmap(g_recs[i].tramp, g_recs[i].tsz);
            g_recs[i].used = 0;
            return INSTR_OK;
        }
    }
    set_err("address %p was not patched by this library", patched_addr);
    return INSTR_ERR_NOTPATCHED;
}