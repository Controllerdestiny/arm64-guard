#!/usr/bin/env python3
# 生成一个"很大"的目标函数,验证大函数支持:
#   - 块前 ~35K 条语句(~100KB+ 代码,超过旧上限 8192 指令扫描)
#   - 块内 ~5K 条语句
#   - 块后 ~35K 条语句
# 总体超过 65K 条指令(旧 MAX_INSNS),用于验证上限提升与越界保护。
import os, sys

N_BEFORE = int(sys.argv[1]) if len(sys.argv) > 1 else 35000
N_BLOCK  = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
N_AFTER  = int(sys.argv[3]) if len(sys.argv) > 3 else 35000
OUT = sys.argv[4] if len(sys.argv) > 4 else "build/libtarget_big.c"

lines = []
lines.append("/* 自动生成:大函数测试目标 */")
lines.append("#include <stdio.h>")
lines.append("")
lines.append("__attribute__((visibility(\"default\")))")
lines.append("int main(int argc) {")
lines.append("    volatile int t = argc;")
lines.append("    /* ===== 块前逻辑(~%d 条语句)===== */" % N_BEFORE)
for i in range(N_BEFORE):
    lines.append("    t = t + %d;" % (i % 7))
lines.append("    asm volatile(\"mov x9, #0x6d0\"); /* 块起始标记 */")
lines.append("    /* ===== 被守卫的代码块 ===== */")
for i in range(N_BLOCK):
    lines.append("    t = t * 3 + %d;" % (i % 5))
lines.append("    printf(\"block ran: t=%%d argc=%%d\\n\", t, argc);")
lines.append("    /* ===== 块结束 ===== */")
lines.append("    asm volatile(\"mov x9, #0x6d1\"); /* 块结束标记 */")
lines.append("    /* ===== 块后逻辑(~%d 条语句)===== */" % N_AFTER)
for i in range(N_AFTER):
    lines.append("    t = t + %d;" % (i % 3))
lines.append("    return t + argc;")
lines.append("}")

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w") as f:
    f.write("\n".join(lines))
print(f"generated {OUT}: {N_BEFORE}+{N_BLOCK}+{N_AFTER} statements")
