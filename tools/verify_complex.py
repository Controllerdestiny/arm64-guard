#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""复杂函数 8 参数守卫的 unicorn 端到端验证。

目标:build/libtarget_complex.so 的 complex_fn(8 个入口参数 + 5KB 大栈帧,
所有参数先压栈)。验证:
  1. 数据流分析把 8 个入口参数**全部**恢复,check 收到的 a0..a7 与入口完全一致
     (任何"错误位置"都会导致不一致 → 失败);
  2. 放行/拒绝两条路径的 printf 调用次数与返回值都正确(整块跳过语义)。
"""
import struct, sys
sys.path.insert(0, "tools")
import verify as V
import unicorn as U
from unicorn.arm64_const import *

DUMP = "build/plan_dump.txt"
TARGET = "build/libtarget_complex.so"

# 8 个互不相同的入口参数(全 64 位)
ARGS = (0x1111111111111111, 0x2222222222222222, 0x3333333333333333,
        0x4444444444444444, 0x5555555555555555, 0x6666666666666666,
        0x7777777777777777, 0x8888888888888888)

dump = open(DUMP, encoding="utf-8", errors="replace").read()
plans = V.parse_plans(dump)
if ("complex", "block") not in plans:
    print("[FAIL] plan_dump.txt 中没有 complex/block 计划(检查 test_logic 调用)")
    sys.exit(1)
guard, patch, words, plen = plans[("complex", "block")]
blob = b"".join(struct.pack("<I", w) for w in words)
print(f"complex guard={guard:#x} plen={plen} tramp_words={len(words)}")

infos = {}
for line in dump.splitlines():
    p = line.split()
    if p and p[0] == "INFO":
        kv = {k: v for k, v in (x.split("=", 1) for x in p[2:])}
        infos[p[1]] = kv
if "complex" not in infos:
    print("[FAIL] dump 中没有 complex INFO 行")
    sys.exit(1)
main_va = int(infos["complex"]["main"], 16)
got = int(infos["complex"]["got"], 16)

data = open(TARGET, "rb").read()
segs = V.load_segments(data)

REGX = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
        UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7]

def run(allow):
    uc = U.Uc(U.UC_ARCH_ARM64, U.UC_MODE_ARM)
    STACK = 0x9000000000
    for (sv, sm, so, sf) in segs:
        base = V.RUNTIME_BASE + sv
        page = base & ~0xFFF
        span = (base - page + sm + 0xFFF) & ~0xFFF
        uc.mem_map(page, span, U.UC_PROT_ALL)
        if sf:
            uc.mem_write(base, data[so:so + sf])
    uc.mem_write(guard, patch)
    uc.mem_map(V.TRAMP_BASE, 0x1000, U.UC_PROT_ALL)
    uc.mem_write(V.TRAMP_BASE, blob)
    uc.mem_map(STACK, 0x100000, U.UC_PROT_ALL)
    uc.mem_map(V.CHECK_ADDR & ~0xFFF, 0x1000, U.UC_PROT_ALL)
    uc.mem_map(V.CALLEE_ADDR & ~0xFFF, 0x1000, U.UC_PROT_ALL)
    uc.mem_write(got, struct.pack("<Q", V.CALLEE_ADDR))
    rec = {"args": None, "printf": 0}

    def on_check(u2, a2, s2, d2):
        rec["args"] = tuple(u2.reg_read(r) for r in REGX)
        u2.reg_write(UC_ARM64_REG_X0, 1 if allow else 0)
        u2.reg_write(UC_ARM64_REG_PC, u2.reg_read(UC_ARM64_REG_X30))

    def on_printf(u2, a2, s2, d2):
        rec["printf"] += 1
        u2.reg_write(UC_ARM64_REG_PC, u2.reg_read(UC_ARM64_REG_X30))

    uc.hook_add(U.UC_HOOK_CODE, on_check, None, V.CHECK_ADDR, V.CHECK_ADDR)
    uc.hook_add(U.UC_HOOK_CODE, on_printf, None, V.CALLEE_ADDR, V.CALLEE_ADDR)
    uc.reg_write(UC_ARM64_REG_SP, STACK + 0x100000 - 0x100)
    for i in range(8):
        uc.reg_write(REGX[i], ARGS[i])
    uc.reg_write(UC_ARM64_REG_X30, 0x1)
    uc.hook_add(U.UC_HOOK_CODE, lambda u3, a3, s3, d3: u3.emu_stop(), None,
                0x1, 0x1)
    try:
        uc.emu_start(main_va, 0x1)
    except U.UcError as e:
        pc = uc.reg_read(UC_ARM64_REG_PC)
        sp = uc.reg_read(UC_ARM64_REG_SP)
        print(f"  [ERR] unicorn: {e}  PC={pc:#x} SP={sp:#x}")
        raise
    return uc.reg_read(UC_ARM64_REG_X0), rec

FAILS = 0
def check(cond, name):
    global FAILS
    print(("  [PASS] " if cond else "  [FAIL] ") + name)
    if not cond:
        FAILS += 1

a = ARGS
t = a[0] ^ a[7]                       # 块前逻辑
exp_pass = (t + sum(a) + a[7] + (a[0] & 0xff)) & 0xFFFFFFFFFFFFFFFF
exp_skip = (t + a[7]) & 0xFFFFFFFFFFFFFFFF

r1, rec1 = run(True)
check(rec1["args"] == ARGS,
      f"放行:check 收到 8 个参数与入口完全一致\n      got={rec1['args']}")
check(rec1["printf"] == 1, f"放行:printf 执行一次 实际 {rec1['printf']}")
check(r1 == exp_pass, f"放行:返回值正确 0x{r1:x}(期望 0x{exp_pass:x})")

r0, rec0 = run(False)
check(rec0["args"] == ARGS,
      f"拒绝:check 同样收到正确参数\n      got={rec0['args']}")
check(rec0["printf"] == 0, f"拒绝:printf 未执行 实际 {rec0['printf']}")
check(r0 == exp_skip, f"拒绝:返回值正确 0x{r0:x}(期望 0x{exp_skip:x})")

print("==" + (" 复杂函数 8 参数守卫全部通过 " if FAILS == 0
              else f" {FAILS} 项失败 ") + "==")
sys.exit(1 if FAILS else 0)
