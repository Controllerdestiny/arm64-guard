/*
 * elf64.h - 在内存中解析 ELF64 模块(运行时已加载的 .so 或文件镜像)
 */
#ifndef ELF64_H
#define ELF64_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 最小 ELF64 结构定义(避免依赖宿主 elf.h) */
typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} elf64_ehdr_t;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} elf64_shdr_t;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} elf64_phdr_t;

typedef struct {
    uint32_t st_name;
    unsigned char st_info;
    unsigned char st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} elf64_sym_t;

typedef struct {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t r_addend;
} elf64_rela_t;

typedef struct {
    uint64_t r_offset;
    uint64_t r_info;
} elf64_rel_t;

#define ELF64_ST_TYPE(i)  ((i) & 0xf)
#define ELF64_ST_BIND(i)  ((i) >> 4)
#define ELF64_R_SYM(i)    ((i) >> 32)
#define ELF64_R_TYPE(i)   ((uint32_t)(i))

/* 常用常量 */
#define EM_AARCH64        183
#define ET_DYN            3
#define PT_LOAD           1
#define SHT_NULL          0
#define SHT_PROGBITS      1
#define SHT_SYMTAB        2
#define SHT_STRTAB        3
#define SHT_RELA          4
#define SHT_HASH          5
#define SHT_DYNAMIC       6
#define SHT_DYNSYM        11
#define SHT_REL           9
#define SHN_UNDEF         0
#define SHN_ABS           0xFFF1
#define SHN_COMMON        0xFFF2
#define STT_NOTYPE        0
#define STT_FUNC          2
#define STB_GLOBAL        1
#define STB_LOCAL         0
#define R_AARCH64_ABS64   257
#define R_AARCH64_GLOB_DAT 1025
#define R_AARCH64_JUMP_SLOT 1026

typedef struct {
    const uint8_t *base;   /* 运行时基址(dlopen 句柄 / 模拟加载基址)      */
    const uint8_t *image;  /* 实际内存镜像(取指用;运行时与 base 相同,      */
                           /* 离线测试可指向文件缓冲区)                    */
    size_t size;           /* 已映射大小(未知可传 0)                      */
    int is_runtime;        /* 1 = 运行时已加载(地址 = base + st_value)    */

    const elf64_ehdr_t *ehdr;
    const elf64_shdr_t *shdrs;
    uint16_t shnum;
    uint16_t shstrndx;

    const char *shstr;
    size_t shstr_size;
    const char *dynstr;
    size_t dynstr_size;
    const char *strtab;
    size_t strtab_size;

    const elf64_sym_t *dynsym;
    size_t dynsym_count;
    const elf64_sym_t *symtab;
    size_t symtab_count;

    const elf64_rela_t *rela_plt;
    size_t rela_plt_count;
    const elf64_rela_t *rela_dyn;
    size_t rela_dyn_count;
    const elf64_rel_t *rel_plt;
    size_t rel_plt_count;
    const elf64_rel_t *rel_dyn;
    size_t rel_dyn_count;

    const uint8_t *plt;
    size_t plt_size;
    uint64_t plt_addr;   /* .plt 的 sh_addr(模块内 VA)                   */
    const uint8_t *got;
    size_t got_size;
    uint64_t got_addr;   /* .got/.got.plt 的 sh_addr(模块内 VA)          */
} elf64_module_t;

/*
 * 解析模块。
 *   base  运行时基址:所有 st_value/sh_addr 都换算为 base + va,
 *         也就是"真实运行时的地址"(dlopen 句柄 / 模拟加载基址)。
 *   image 实际内存镜像:取指/读节表从这里读。
 *         (base == image 表示运行时场景;离线测试可让 image 指向文件缓冲区,
 *          base 指向一个模拟的加载地址。)
 *   size  image 已知大小(未知传 0)。
 * 返回 0 成功。
 */
int elf64_module_init(elf64_module_t *m, const void *base, const void *image,
                      size_t size);

/* 按名称查找符号(优先 symtab,再 dynsym)。成功返回 0,
 * 输出运行时地址 *va 与大小 *size(可为 NULL)。 */
int elf64_find_symbol(const elf64_module_t *m, const char *name,
                      uint64_t *va, uint64_t *size);

/*
 * 查找未定义函数符号(如 "printf")对应的 PLT 桩地址与 GOT 槽地址。
 * plt_va/got_va 均为运行时地址;got_va 处(运行时)存有解析后的函数地址。
 * 成功返回 0。
 */
int elf64_find_plt(const elf64_module_t *m, const char *name,
                   uint64_t *plt_va, uint64_t *got_va);

/* 把模块内地址(st_value / sh_addr)换算为运行时地址 */
uint64_t elf64_runtime_addr(const elf64_module_t *m, uint64_t module_va);

/*
 * 把运行时地址换算为镜像内偏移(用于取指)。
 * 运行时场景(base == image):返回 va - base;
 * 离线镜像:按节表 [sh_addr, sh_addr+sh_size) 反查 sh_offset。
 * 失败返回 -1。
 */
ptrdiff_t elf64_va_to_offset(const elf64_module_t *m, uint64_t va);

#ifdef __cplusplus
}
#endif

#endif /* ELF64_H */
