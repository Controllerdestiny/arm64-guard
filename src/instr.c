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
#include <stdlib.h>

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
    int page_refs;  /* 共享同一 mmap 页面的记录数(快照模式=2,普通=1) */
    /* 外部回跳补丁区的分支重映射(卸载时需恢复原指令) */
    uint64_t fix_addr[INSTR_FIX_MAX];
    uint32_t fix_orig[INSTR_FIX_MAX];
    int fix_count;
} rec_t;

static rec_t g_recs[MAX_RECS];

static int patch_register(uint64_t addr, const uint8_t *orig, int len,
                          uint8_t *tramp, size_t tsz,
                          const instr_fix_t *fixes, int fix_count,
                          int page_refs) {
    for (int i = 0; i < MAX_RECS; i++) {
        if (!g_recs[i].used) {
            g_recs[i].addr = addr;
            memcpy(g_recs[i].orig, orig, (size_t)len);
            g_recs[i].len = len;
            g_recs[i].tramp = tramp;
            g_recs[i].tsz = tsz;
            g_recs[i].used = 1;
            g_recs[i].page_refs = page_refs;
            g_recs[i].fix_count = fix_count < INSTR_FIX_MAX ? fix_count
                                                            : INSTR_FIX_MAX;
            for (int j = 0; j < g_recs[i].fix_count; j++) {
                g_recs[i].fix_addr[j] = fixes[j].addr;
                g_recs[i].fix_orig[j] = fixes[j].orig_insn;
            }
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

/*
 * 安全取指:先做边界检查再 memcpy,杜绝读未映射内存导致 SIGSEGV。
 * 边界由 elf64_module_init 通过 PT_LOAD 推导(size>0);地址 < base 一律拒绝。
 */
static uint32_t fetch_runtime(void *ctx, uint64_t addr) {
    const elf64_module_t *m = (const elf64_module_t *)ctx;
    if (!m->base || addr < (uint64_t)(uintptr_t)m->base)
        return 0;
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

/*
 * 无符号大小:扫到最后一个 ret(上限 1M 条指令 = 4MB,支持很大的函数)。
 * 遇到连续 0 字(数据/对齐填充)继续跳过,而非直接 break —— 巨型函数内
 * 偶发的 0 字(如跳转表)不应截断函数末尾扫描。
 */
static uint64_t scan_fn_end(const elf64_module_t *m, uint64_t va) {
    uint64_t last = va + 4;
    int zeros = 0;
    for (uint64_t pc = va; pc < va + (1u << 20) * 4; pc += 4) {
        uint32_t w = fetch_runtime((void *)m, pc);
        if (!w) {
            if (++zeros >= 64)   /* 连续 64 字(256B)为 0,视为到达函数末尾 */
                break;
            continue;
        }
        zeros = 0;
        a64_insn_t d;
        a64_decode(pc, w, &d);
        if (d.kind == A64_RET)
            last = pc + 4;
    }
    return last;
}

/* ---------------- 规划并应用一次守卫 ---------------- */

/*
 * snap_mode:1 = 入口快照模式 —— 同时在 fn 入口打参数快照补丁,
 * 守卫点参数从快照区读取(100% 可恢复,与函数内部复杂度无关)。
 * 快照补丁与守卫补丁共享同一个 mmap(2 页),卸载时按引用计数释放。
 */
static int apply_plan(const elf64_module_t *m, uint64_t cstart, uint64_t cend,
                      uint64_t guard, int is_call_guard, uint64_t block_end,
                      uint64_t check, uint64_t callee, int snap_mode,
                      uint64_t prev_hook) {
    instr_plan_t plan;
    instr_plan_t ep; /* 入口快照计划(仅 snap_mode 使用) */
    int rc;

    /* 预规划(基址未知):校验参数与分析是否可行 */
    rc = instr_plan_guard(m, cstart, cend, guard, is_call_guard,
                          block_end, check, callee, 0,
                          snap_mode ? 0x1000 : 0, &plan);
    if (rc != INSTR_OK) {
        set_err("plan failed: %d at guard %p", rc, (void *)(uintptr_t)guard);
        return rc;
    }
    if (plan.tramp_words == 0) {
        set_err("empty trampoline");
        return INSTR_ERR_OTHER;
    }
    if (snap_mode) {
        rc = instr_plan_entry_snapshot(m, cstart, block_end, 0x1000, 0x2000,
                                       prev_hook, &ep);
        if (rc != INSTR_OK) {
            set_err("entry snapshot plan failed: %d", rc);
            return rc;
        }
    }

    size_t pages = snap_mode ? 2 : 1;
    uint8_t *tramp = mmap(NULL, TRAMP_PAGE * pages,
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (tramp == MAP_FAILED) {
        set_err("mmap trampoline failed");
        return INSTR_ERR_MMAP;
    }

    /* 快照区与入口 trampoline 放在第 2 页 */
    uint64_t snap = 0, entry_base = 0;
    if (snap_mode) {
        entry_base = (uint64_t)(uintptr_t)tramp + TRAMP_PAGE;
        snap = entry_base + 0x200; /* 入口 trampoline 之后,页内互不重叠 */
    }

    /* 以真实基址重新规划(被搬移的 PC 相对指令需要真实地址) */
    rc = instr_plan_guard(m, cstart, cend, guard, is_call_guard, block_end,
                          check, callee, (uint64_t)(uintptr_t)tramp, snap,
                          &plan);
    if (rc != INSTR_OK) {
        set_err("re-plan failed: %d", rc);
        munmap(tramp, TRAMP_PAGE * pages);
        return rc;
    }
    size_t tsz = plan.tramp_words * 4;
    memcpy(tramp, plan.tramp, tsz);
    __builtin___clear_cache((char *)tramp, (char *)tramp + (long)tsz);

    if (getenv("INSTR_DEBUG")) {
        fprintf(stderr,
                "[instr] guard=%p cstart=%p cend=%p plen=%d fix_count=%d "
                "tramp_words=%zu snap=%d\n",
                (void *)(uintptr_t)guard, (void *)(uintptr_t)cstart,
                (void *)(uintptr_t)cend, plan.patch_len, plan.fix_count,
                plan.tramp_words, snap_mode);
        for (int i = 0; i < plan.fix_count; i++)
            fprintf(stderr, "[instr]   fix[%d] @%p: 0x%08x -> 0x%08x\n", i,
                    (void *)(uintptr_t)plan.fixes[i].addr,
                    plan.fixes[i].orig_insn, plan.fixes[i].new_insn);
    }

    /* ---- 入口快照补丁:先应用(守卫补丁与它互不重叠) ---- */
    if (snap_mode) {
        rc = instr_plan_entry_snapshot(m, cstart, block_end, snap,
                                       entry_base, prev_hook, &ep);
        if (rc != INSTR_OK) {
            set_err("entry snapshot re-plan failed: %d", rc);
            munmap(tramp, TRAMP_PAGE * pages);
            return rc;
        }
        size_t etsz = ep.tramp_words * 4;
        memcpy(tramp + TRAMP_PAGE, ep.tramp, etsz);
        __builtin___clear_cache((char *)tramp + TRAMP_PAGE,
                                (char *)tramp + TRAMP_PAGE + (long)etsz);

        rc = apply_bytes((void *)(uintptr_t)ep.addr, ep.patch, ep.patch_len);
        if (rc != INSTR_OK) {
            munmap(tramp, TRAMP_PAGE * pages);
            return rc;
        }
        for (int i = 0; i < ep.fix_count; i++) {
            rc = apply_bytes((void *)(uintptr_t)ep.fixes[i].addr,
                             (const uint8_t *)&ep.fixes[i].new_insn, 4);
            if (rc != INSTR_OK) {
                for (int j = 0; j < i; j++)
                    apply_bytes((void *)(uintptr_t)ep.fixes[j].addr,
                                (const uint8_t *)&ep.fixes[j].orig_insn, 4);
                apply_bytes((void *)(uintptr_t)ep.addr, ep.orig,
                            ep.patch_len);
                munmap(tramp, TRAMP_PAGE * pages);
                return rc;
            }
        }
        rc = patch_register(ep.addr, ep.orig, ep.patch_len, tramp,
                            TRAMP_PAGE * pages, ep.fixes, ep.fix_count, 2);
        if (rc != INSTR_OK) {
            munmap(tramp, TRAMP_PAGE * pages);
            return rc;
        }
    }

    /* ---- 守卫补丁 ---- */
    rc = apply_bytes((void *)(uintptr_t)guard, plan.patch, plan.patch_len);
    if (rc != INSTR_OK) {
        if (snap_mode) { /* 回滚入口补丁 */
            apply_bytes((void *)(uintptr_t)ep.addr, ep.orig, ep.patch_len);
            for (int j = 0; j < ep.fix_count; j++)
                apply_bytes((void *)(uintptr_t)ep.fixes[j].addr,
                            (const uint8_t *)&ep.fixes[j].orig_insn, 4);
        }
        munmap(tramp, TRAMP_PAGE * pages);
        return rc;
    }

    for (int i = 0; i < plan.fix_count; i++) {
        rc = apply_bytes((void *)(uintptr_t)plan.fixes[i].addr,
                         (const uint8_t *)&plan.fixes[i].new_insn, 4);
        if (rc != INSTR_OK) {
            /* 回滚已应用的 fix,恢复主补丁;快照模式一并回滚入口补丁 */
            for (int j = 0; j < i; j++)
                apply_bytes((void *)(uintptr_t)plan.fixes[j].addr,
                            (const uint8_t *)&plan.fixes[j].orig_insn, 4);
            apply_bytes((void *)(uintptr_t)guard, plan.orig, plan.patch_len);
            if (snap_mode) {
                apply_bytes((void *)(uintptr_t)ep.addr, ep.orig, ep.patch_len);
                for (int j = 0; j < ep.fix_count; j++)
                    apply_bytes((void *)(uintptr_t)ep.fixes[j].addr,
                                (const uint8_t *)&ep.fixes[j].orig_insn, 4);
            }
            munmap(tramp, TRAMP_PAGE * pages);
            return rc;
        }
    }
    return patch_register(guard, plan.orig, plan.patch_len, tramp,
                          TRAMP_PAGE * pages, plan.fixes, plan.fix_count,
                          snap_mode ? 2 : 1);
}

/* ---------------- 公共 API ---------------- */

/*
 * 初始化模块用于分析与规划。优先打开磁盘上的 .so 文件作为指令镜像:
 * 即使函数入口已被其它 hook 框架(如 Dobby)先行改写,分析器仍读到
 * 原始指令字节,参数分析不受影响;打开失败(内存加载 / 无读权限 /
 * 被 strip 无节头)则回退到读运行时内存。
 * *filebuf_out 需要调用方在 apply 完成后 free(失败时为 NULL)。
 */
static int init_module(elf64_module_t *m, void *fbase, const char *fname,
                       uint8_t **filebuf_out, size_t *filesz_out) {
    *filebuf_out = NULL;
    *filesz_out = 0;
    if (fname && fname[0]) {
        FILE *f = fopen(fname, "rb");
        if (f) {
            if (fseek(f, 0, SEEK_END) == 0) {
                long n = ftell(f);
                if (n > 0) {
                    fseek(f, 0, SEEK_SET);
                    uint8_t *buf = (uint8_t *)malloc((size_t)n);
                    if (buf && fread(buf, 1, (size_t)n, f) == (size_t)n) {
                        /* 离线镜像路径需要节表,失败则释放并回退 */
                        if (elf64_module_init(m, fbase, buf, (size_t)n) == 0 &&
                            m->shnum > 0) {
                            *filebuf_out = buf;
                            *filesz_out = (size_t)n;
                            fclose(f);
                            return 0;
                        }
                        free(buf);
                    } else if (buf) {
                        free(buf);
                    }
                }
            }
            fclose(f);
        }
    }
    /* 回退:读运行时内存(不带节头) */
    return elf64_module_init(m, fbase, NULL, 0);
}

/*
 * 快照模式安装前的"入口占用检测":
 *   - 有磁盘镜像:逐字节对比运行时入口 16 字节与镜像 —— 不一致即被占用;
 *   - 无镜像:启发式识别绝对跳转补丁形态(ldr x16,[pc,#8]; br x16,
 *     与 Dobby/本库的形态 B 一致)。
 * 返回 1 = 入口已被占用(拒绝安装),0 = 空闲。
 */
static int entry_busy(const elf64_module_t *m, uint64_t fn) {
    if (m->image && m->image != m->base) {
        const uint8_t *live = (const uint8_t *)(uintptr_t)fn;
        for (int i = 0; i < 16; i++) {
            ptrdiff_t off = elf64_va_to_offset(m, fn + (uint64_t)i);
            if (off < 0)
                return 1; /* 镜像读不到对应字节,保守拒绝 */
            if (live[i] != ((const uint8_t *)m->image)[off])
                return 1;
        }
        return 0;
    }
    uint32_t w0, w1;
    memcpy(&w0, (void *)(uintptr_t)fn, 4);
    memcpy(&w1, (void *)(uintptr_t)fn + 4, 4);
    return w0 == a64_insn_ldr_lit(16, 1, fn + 8, fn) && w1 == a64_insn_br(16);
}

/*
 * 解析入口上现有 hook 的跳转目标(链式共存用):
 *   - 形态 B:ldr x16, [pc, #8]; br x16; .quad target —— 从运行时读 .quad;
 *   - 形态 A:adrp x16, page; add x16, x16, #lo12; br x16 —— 解码计算。
 * 返回 hook trampoline 地址;无法识别返回 0(调用方应拒绝,避免覆盖)。
 */
static uint64_t parse_prev_hook(uint64_t fn) {
    uint32_t w0, w1, w2;
    memcpy(&w0, (void *)(uintptr_t)fn, 4);
    memcpy(&w1, (void *)(uintptr_t)fn + 4, 4);
    memcpy(&w2, (void *)(uintptr_t)fn + 8, 4);
    a64_insn_t d0, d1, d2;
    a64_decode(fn, w0, &d0);
    a64_decode(fn + 4, w1, &d1);
    a64_decode(fn + 8, w2, &d2);
    if (d0.kind == A64_LDR_LIT && d0.rt == 16 && d0.target == fn + 8 &&
        d1.kind == A64_BR && d1.rn == 16) {
        uint64_t tgt;
        memcpy(&tgt, (void *)(uintptr_t)fn + 8, 8);
        return tgt;
    }
    if (d0.kind == A64_ADRP && d0.rd == 16 && d1.kind == A64_ADD_IMM &&
        d1.rd == 16 && d1.rn == 16 && d2.kind == A64_BR && d2.rn == 16) {
        return d0.page + (uint64_t)d1.imm;
    }
    return 0;
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
    uint8_t *img = NULL;
    size_t imgsz = 0;
    if (init_module(&m, info.dli_fbase, info.dli_fname, &img, &imgsz) != 0) {
        set_err("module at %p is not an AArch64 ELF", info.dli_fbase);
        return INSTR_ERR_NOT_ELF;
    }
    uint64_t cstart = (uint64_t)(uintptr_t)fn;
    uint64_t bstart = (uint64_t)(uintptr_t)block_start;
    uint64_t bend = (uint64_t)(uintptr_t)block_end;

    /* 参数合法性:入口/块首/块尾都必须在模块映射范围内 */
    if (bstart < cstart || bstart >= (uint64_t)(uintptr_t)m.base + m.size ||
        bend <= bstart || bend > (uint64_t)(uintptr_t)m.base + m.size) {
        set_err("block [%p, %p) out of module range base=%p size=0x%zx",
                block_start, block_end, (void *)m.base, m.size);
        free(img);
        return INSTR_ERR_RANGE;
    }

    uint64_t cend = scan_fn_end(&m, cstart); /* 支持很大的函数 */
    int rc = apply_plan(&m, cstart, cend, bstart, 0, bend,
                        (uint64_t)(uintptr_t)check, 0, 0, 0);
    free(img);
    return rc;
}

int instr_guard_block_snap(void *fn, void *block_start, void *block_end,
                           void *check) {
    if (!fn || !block_start || !block_end || !check) {
        set_err("invalid argument");
        return INSTR_ERR_ARG;
    }
    Dl_info info;
    if (!dladdr(fn, &info) || !info.dli_fbase) {
        set_err("dladdr(%p) failed: address not in a loaded module", fn);
        return INSTR_ERR_ARG;
    }
    elf64_module_t m;
    uint8_t *img = NULL;
    size_t imgsz = 0;
    if (init_module(&m, info.dli_fbase, info.dli_fname, &img, &imgsz) != 0) {
        set_err("module at %p is not an AArch64 ELF", info.dli_fbase);
        return INSTR_ERR_NOT_ELF;
    }
    uint64_t cstart = (uint64_t)(uintptr_t)fn;
    uint64_t bstart = (uint64_t)(uintptr_t)block_start;
    uint64_t bend = (uint64_t)(uintptr_t)block_end;

    /* 快照模式会改写 fn 入口 16 字节,块首必须在其之后 */
    if (bstart < cstart + 16 ||
        bstart >= (uint64_t)(uintptr_t)m.base + m.size ||
        bend <= bstart || bend > (uint64_t)(uintptr_t)m.base + m.size) {
        set_err("block [%p, %p) invalid for snapshot mode (need block_start "
                ">= fn+16, in-module)", block_start, block_end);
        free(img);
        return INSTR_ERR_RANGE;
    }

    /* 入口占用检测:与 Dobby 等 hook 框架互斥,拒绝静默互相覆盖。
     * 若入口已被占用且 hook 形态可解析(ldr/br 或 adrp/add/br),则进入
     * 链式共存:快照 trampoline 保存参数后直接跳进现有 hook 的 trampoline。 */
    uint64_t prev_hook = 0;
    if (entry_busy(&m, cstart)) {
        prev_hook = parse_prev_hook(cstart);
        if (prev_hook == 0) {
            set_err("entry of %p is hooked by an unrecognized framework; "
                    "cannot chain snapshot guard", fn);
            free(img);
            return INSTR_ERR_ENTRY_BUSY;
        }
        /* 同一函数重复安装快照守卫:入口已是我们自己的补丁,拒绝 */
        for (int i = 0; i < MAX_RECS; i++) {
            if (g_recs[i].used && g_recs[i].addr == cstart) {
                set_err("snapshot guard already installed on %p", fn);
                free(img);
                return INSTR_ERR_ENTRY_BUSY;
            }
        }
    }

    uint64_t cend = scan_fn_end(&m, cstart);
    int rc = apply_plan(&m, cstart, cend, bstart, 0, bend,
                        (uint64_t)(uintptr_t)check, 0, 1, prev_hook);
    free(img);
    return rc;
}

int instr_unpatch(void *patched_addr) {
    uint64_t a = (uint64_t)(uintptr_t)patched_addr;
    for (int i = 0; i < MAX_RECS; i++) {
        if (g_recs[i].used && g_recs[i].addr == a) {
            /* 先恢复外部回跳分支的重映射(原指令已保存) */
            for (int j = 0; j < g_recs[i].fix_count; j++) {
                int rc = apply_bytes((void *)(uintptr_t)g_recs[i].fix_addr[j],
                                     (const uint8_t *)&g_recs[i].fix_orig[j], 4);
                if (rc != INSTR_OK)
                    return rc;
            }
            int rc = apply_bytes((void *)(uintptr_t)a, g_recs[i].orig,
                                 (size_t)g_recs[i].len);
            if (rc != INSTR_OK)
                return rc;
            g_recs[i].used = 0;
            /* 快照模式:入口与守卫共享同一 mmap,引用计数归零才释放 */
            g_recs[i].page_refs--;
            if (g_recs[i].page_refs <= 0)
                munmap(g_recs[i].tramp, g_recs[i].tsz);
            return INSTR_OK;
        }
    }
    set_err("address %p was not patched by this library", patched_addr);
    return INSTR_ERR_NOTPATCHED;
}