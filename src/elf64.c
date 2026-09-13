/*
 * elf64.c - 在内存中解析 ELF64 模块
 *
 * 支持两种场景:
 *  1) 运行时:base = dlopen 句柄(ET_DYN 的加载基址),地址 = base + st_value
 *  2) 文件镜像:base = 文件字节起始,模块内地址按镜像偏移解释
 */
#include "elf64.h"

#include <string.h>
#include <stdint.h>

/* 用于 PLT 桩扫描的解码(避免依赖 a64.c:只需 adrp + ldr imm) */
static uint32_t read32(const uint8_t *p) {
    uint32_t w;
    memcpy(&w, p, 4);
    return w;
}

static int is_adrp_x16(uint32_t w) {
    /* adrp x16:bits[31:24] = 11000000 形式,rd=16 */
    return (w & 0x9F000000) == 0x90000000 && (w & 31) == 16;
}

static int is_ldr_x17_x16(uint32_t w, int64_t *imm) {
    /* ldr x17, [x16, #imm12](无符号立即数) */
    if ((w & 0xFFC00000) != 0xF9400000)
        return 0;
    if ((w & 31) != 17 || ((w >> 5) & 31) != 16)
        return 0;
    *imm = (int64_t)((w >> 10) & 0xFFF) << 3;
    return 1;
}

static const char *sym_name(const elf64_module_t *m, const elf64_sym_t *sym,
                            int in_dynsym) {
    const char *str = in_dynsym ? m->dynstr : m->strtab;
    size_t size = in_dynsym ? m->dynstr_size : m->strtab_size;
    if (!str || sym->st_name >= size)
        return NULL;
    return str + sym->st_name;
}

int elf64_module_init(elf64_module_t *m, const void *base, const void *image,
                      size_t size) {
    if (!m || !base)
        return -1;
    memset(m, 0, sizeof(*m));
    m->base = (const uint8_t *)base;
    m->image = image ? (const uint8_t *)image : (const uint8_t *)base;
    m->size = size;

    /* 文件头校验(从镜像读取) */
    if (size > 0 && size < 64)
        return -1;
    const uint8_t *img = m->image;
    const elf64_ehdr_t *eh = (const elf64_ehdr_t *)img;
    if (memcmp(eh->e_ident, "\x7f" "ELF", 4) != 0)
        return -1;
    if (eh->e_ident[4] != 2) /* ELFCLASS64 */
        return -1;
    if (eh->e_ident[5] != 1) /* 小端 */
        return -1;
    if (eh->e_machine != EM_AARCH64)
        return -1;
    m->ehdr = eh;
    m->shnum = eh->e_shnum;
    m->shstrndx = eh->e_shstrndx;

    /*
     * 用 program headers(PT_LOAD)推导模块映射范围。调用方传 size=0(未知)时,
     * fetch 系列函数需要知道边界才能安全取指(否则可能读未映射内存 SIGSEGV)。
     * 运行时场景:PT_LOAD 的 p_vaddr+p_memsz 即模块映射上界(相对基址)。
     * 注意 p_vaddr 是模块内偏移(ET_DYN 基址为 0),== RVA。
     */
    if (m->size == 0 && eh->e_phoff != 0 && eh->e_phnum > 0) {
        const elf64_phdr_t *phs =
            (const elf64_phdr_t *)(img + eh->e_phoff);
        uint64_t max_end = 0;
        for (int i = 0; i < eh->e_phnum; i++) {
            if (phs[i].p_type == PT_LOAD) {
                uint64_t end = phs[i].p_vaddr + phs[i].p_memsz;
                if (end > max_end)
                    max_end = end;
            }
        }
        if (max_end > 0 && max_end != UINT64_MAX)
            m->size = (size_t)max_end;
    }

    if (eh->e_shoff == 0 || eh->e_shnum == 0)
        return 0; /* 无节头(被 strip 的情况),后续查找都会失败 */

    /*
     * 运行时(live)模块保护:Android 只映射 PT_LOAD 段,节头表(e_shoff,文件偏移)
     * 未必映射在 base+e_shoff。生产 libil2cpp.so 经常读不到 → 节头是垃圾,
     * 直接 strcmp 节名会解引用垃圾指针(SIGSEGV)。
     * 策略:live 运行时(image == base)一律跳过节头 —— block-guard 的取指走
     * elf64_va_to_offset 的 va-base 分支,不依赖符号/PLT;
     * 离线镜像(image != base,文件缓冲区)才解析节头(带边界校验)。
     */
    if (m->image == m->base) {
        m->shnum = 0;
        return 0;
    }

    size_t shdr_bytes = (size_t)eh->e_shnum * sizeof(elf64_shdr_t);
    if (m->size) {
        if ((uint64_t)eh->e_shoff > m->size ||
            shdr_bytes > m->size - (size_t)eh->e_shoff)
            return 0;
    } else {
        m->shnum = 0;
        return 0;
    }

    const elf64_shdr_t *shdrs =
        (const elf64_shdr_t *)(img + eh->e_shoff);
    m->shdrs = shdrs;

    /* 节名字符串表 */
    if (m->shstrndx < m->shnum) {
        const elf64_shdr_t *sh = &shdrs[m->shstrndx];
        if (sh->sh_offset <= m->size &&
            sh->sh_size <= m->size - (size_t)sh->sh_offset) {
            m->shstr = (const char *)img + sh->sh_offset;
            m->shstr_size = (size_t)sh->sh_size;
        }
    }

    for (int i = 0; i < m->shnum; i++) {
        const elf64_shdr_t *sh = &shdrs[i];
        const char *name = NULL;
        if (m->shstr && sh->sh_name < m->shstr_size)
            name = m->shstr + sh->sh_name;
        if (!name)
            continue;
        /* 数据区也需在模块范围内,否则后续符号解析会解引用垃圾指针 */
        if (sh->sh_offset > m->size ||
            sh->sh_size > m->size - (size_t)sh->sh_offset)
            continue;
        const uint8_t *p = img + sh->sh_offset;
        if (strcmp(name, ".dynsym") == 0) {
            m->dynsym = (const elf64_sym_t *)p;
            m->dynsym_count = (size_t)(sh->sh_size / sizeof(elf64_sym_t));
        } else if (strcmp(name, ".dynstr") == 0) {
            m->dynstr = (const char *)p;
            m->dynstr_size = (size_t)sh->sh_size;
        } else if (strcmp(name, ".symtab") == 0) {
            m->symtab = (const elf64_sym_t *)p;
            m->symtab_count = (size_t)(sh->sh_size / sizeof(elf64_sym_t));
        } else if (strcmp(name, ".strtab") == 0) {
            m->strtab = (const char *)p;
            m->strtab_size = (size_t)sh->sh_size;
        } else if (strcmp(name, ".rela.plt") == 0) {
            m->rela_plt = (const elf64_rela_t *)p;
            m->rela_plt_count = (size_t)(sh->sh_size / sizeof(elf64_rela_t));
        } else if (strcmp(name, ".rela.dyn") == 0) {
            m->rela_dyn = (const elf64_rela_t *)p;
            m->rela_dyn_count = (size_t)(sh->sh_size / sizeof(elf64_rela_t));
        } else if (strcmp(name, ".rel.plt") == 0) {
            m->rel_plt = (const elf64_rel_t *)p;
            m->rel_plt_count = (size_t)(sh->sh_size / sizeof(elf64_rel_t));
        } else if (strcmp(name, ".rel.dyn") == 0) {
            m->rel_dyn = (const elf64_rel_t *)p;
            m->rel_dyn_count = (size_t)(sh->sh_size / sizeof(elf64_rel_t));
        } else if (strcmp(name, ".plt") == 0) {
            m->plt = p;
            m->plt_size = (size_t)sh->sh_size;
            m->plt_addr = sh->sh_addr;
        } else if (strcmp(name, ".got") == 0 || strcmp(name, ".got.plt") == 0) {
            m->got = p;
            m->got_size = (size_t)sh->sh_size;
            m->got_addr = sh->sh_addr;
        }
    }
    return 0;
}

uint64_t elf64_runtime_addr(const elf64_module_t *m, uint64_t module_va) {
    return (uint64_t)(uintptr_t)m->base + module_va;
}

ptrdiff_t elf64_va_to_offset(const elf64_module_t *m, uint64_t va) {
    if (m->base == m->image)
        return (ptrdiff_t)(va - (uint64_t)(uintptr_t)m->base);
    /* 离线镜像:运行时地址 -> 模块内地址 -> 文件偏移(按节表反查) */
    uint64_t mva = va - (uint64_t)(uintptr_t)m->base;
    for (int i = 0; i < m->shnum; i++) {
        const elf64_shdr_t *sh = &m->shdrs[i];
        if (sh->sh_addr == 0)
            continue;
        if (mva >= sh->sh_addr && mva < sh->sh_addr + sh->sh_size)
            return (ptrdiff_t)(sh->sh_offset + (mva - sh->sh_addr));
    }
    return -1;
}

static int sym_is_func(const elf64_sym_t *sym) {
    int type = ELF64_ST_TYPE(sym->st_info);
    return type == STT_FUNC || type == STT_NOTYPE;
}

int elf64_find_symbol(const elf64_module_t *m, const char *name,
                      uint64_t *va, uint64_t *size) {
    if (!m || !name)
        return -1;
    /* 优先 .symtab(包含局部符号) */
    for (int pass = 0; pass < 2; pass++) {
        const elf64_sym_t *tab = pass == 0 ? m->symtab : m->dynsym;
        size_t count = pass == 0 ? m->symtab_count : m->dynsym_count;
        if (!tab)
            continue;
        for (size_t i = 0; i < count; i++) {
            const elf64_sym_t *s = &tab[i];
            if (s->st_shndx == SHN_UNDEF)
                continue;
            if (!sym_is_func(s))
                continue;
            const char *n = sym_name(m, s, pass == 1);
            if (n && strcmp(n, name) == 0) {
                if (va)
                    *va = elf64_runtime_addr(m, s->st_value);
                if (size)
                    *size = s->st_size;
                return 0;
            }
        }
    }
    return -1;
}

int elf64_find_plt(const elf64_module_t *m, const char *name,
                   uint64_t *plt_va, uint64_t *got_va) {
    if (!m || !name || !m->dynsym || !m->dynstr)
        return -1;
    size_t idx = 0;
    int found = 0;
    uint64_t got_off = 0;

    for (size_t i = 0; i < m->rela_plt_count; i++) {
        const elf64_rela_t *r = &m->rela_plt[i];
        uint32_t type = ELF64_R_TYPE(r->r_info);
        if (type != R_AARCH64_JUMP_SLOT)
            continue;
        size_t symidx = (size_t)ELF64_R_SYM(r->r_info);
        if (symidx >= m->dynsym_count)
            continue;
        const elf64_sym_t *s = &m->dynsym[symidx];
        const char *n = sym_name(m, s, 1);
        if (n && strcmp(n, name) == 0) {
            idx = i;
            got_off = r->r_offset;
            found = 1;
            break;
        }
    }
    if (!found && m->rel_plt) {
        for (size_t i = 0; i < m->rel_plt_count; i++) {
            const elf64_rel_t *r = &m->rel_plt[i];
            uint32_t type = ELF64_R_TYPE(r->r_info);
            if (type != R_AARCH64_JUMP_SLOT)
                continue;
            size_t symidx = (size_t)ELF64_R_SYM(r->r_info);
            if (symidx >= m->dynsym_count)
                continue;
            const elf64_sym_t *s = &m->dynsym[symidx];
            const char *n = sym_name(m, s, 1);
            if (n && strcmp(n, name) == 0) {
                idx = i;
                got_off = r->r_offset;
                found = 1;
                break;
            }
        }
    }
    if (!found || !m->plt || m->plt_size == 0)
        return -1;

    /* 扫描 .plt,找引用 printf GOT 槽的桩:adrp x16, page; ldr x17, [x16, #off] */
    uint64_t plt_runtime = elf64_runtime_addr(m, m->plt_addr);
    for (size_t off = 0; off + 8 <= m->plt_size; off += 4) {
        uint32_t w1 = read32(m->plt + off);
        if (!is_adrp_x16(w1))
            continue;
        uint64_t adrp_page = (plt_runtime + off) & ~(uint64_t)0xFFF;
        /* adrp imm 字段(bits 23:22 immlo, 21:5 immhi) */
        int64_t immhi = (int64_t)((w1 >> 5) & 0x7FFFF);
        if (immhi & (1LL << 18))
            immhi -= (1LL << 19); /* 符号扩展 19 位 */
        int64_t immlo = (w1 >> 22) & 3;
        adrp_page += ((immhi << 2) | immlo) << 12;

        int64_t imm2;
        uint32_t w2 = read32(m->plt + off + 4);
        if (!is_ldr_x17_x16(w2, &imm2))
            continue;
        if (adrp_page + imm2 == elf64_runtime_addr(m, got_off)) {
            if (plt_va)
                *plt_va = plt_runtime + off;
            if (got_va)
                *got_va = elf64_runtime_addr(m, got_off);
            return 0;
        }
    }

    /* 退化:按固定 16 字节桩布局估算(旧工具链) */
    {
        uint64_t plt_base = plt_runtime;
        if (plt_va)
            *plt_va = plt_base + 16 + idx * 16;
        if (got_va)
            *got_va = elf64_runtime_addr(m, got_off);
        return 0;
    }
}
