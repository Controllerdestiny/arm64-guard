#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""临时验证:C++ 实例方法 _ZN3Foo4workEi 的代码块守卫(unicorn 端到端)"""
import sys, struct
sys.path.insert(0, "tools")
import verify as V
import unicorn as U
from unicorn.arm64_const import *

dump = open("build/plan_dump_cpp.txt", encoding="utf-8", errors="replace").read()
plans = V.parse_plans(dump)
guard, patch, words, plen = plans[("block", "block")]
blob = b"".join(struct.pack("<I", w) for w in words)
data = open("build/libtarget_cpp.so", "rb").read()
segs = V.load_segments(data)
main_va = 0x4000004698
got = 0x4000008938
THIS = 0x7000001000

def run(n):
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
    uc.mem_map(STACK, 0x10000, U.UC_PROT_ALL)
    uc.mem_map(V.CHECK_ADDR & ~0xFFF, 0x1000, U.UC_PROT_ALL)
    uc.mem_map(V.CALLEE_ADDR & ~0xFFF, 0x1000, U.UC_PROT_ALL)
    uc.mem_write(got, struct.pack("<Q", V.CALLEE_ADDR))
    uc.mem_map(THIS & ~0xFFF, 0x1000, U.UC_PROT_ALL)
    uc.mem_write(THIS, struct.pack("<i", 10))  # this->base = 10
    rec = {"check": [], "printf": 0}

    def on_check(u2, a2, s2, d2):
        x0 = u2.reg_read(UC_ARM64_REG_X0)
        x1 = u2.reg_read(UC_ARM64_REG_X1)
        rec["check"].append((x0, x1))
        u2.reg_write(UC_ARM64_REG_X0, 1 if x1 != 0 else 0)
        u2.reg_write(UC_ARM64_REG_PC, u2.reg_read(UC_ARM64_REG_X30))

    def on_printf(u2, a2, s2, d2):
        rec["printf"] += 1
        u2.reg_write(UC_ARM64_REG_PC, u2.reg_read(UC_ARM64_REG_X30))

    uc.hook_add(U.UC_HOOK_CODE, on_check, None, V.CHECK_ADDR, V.CHECK_ADDR)
    uc.hook_add(U.UC_HOOK_CODE, on_printf, None, V.CALLEE_ADDR, V.CALLEE_ADDR)
    uc.reg_write(UC_ARM64_REG_SP, STACK + 0x10000 - 0x100)
    uc.reg_write(UC_ARM64_REG_X0, THIS)
    uc.reg_write(UC_ARM64_REG_X1, n)
    uc.reg_write(UC_ARM64_REG_X30, 0x1)
    uc.hook_add(U.UC_HOOK_CODE, lambda u3, a3, s3, d3: u3.emu_stop(), None,
                0x1, 0x1)
    uc.emu_start(main_va, 0x1)
    return uc.reg_read(UC_ARM64_REG_X0), rec

FAILS = 0
def check(cond, name):
    global FAILS
    print(("  [PASS] " if cond else "  [FAIL] ") + name)
    if not cond:
        FAILS += 1

r0, rec0 = run(0)
check(r0 == 10, f"work(0) 返回 10(base,块跳过) 实际 {r0}")
check(rec0["printf"] == 0, f"work(0) printf 未执行 实际 {rec0['printf']}")
check(rec0["check"] == [(THIS, 0)],
      f"work(0) mycheck 收到 (this, n=0) 实际 {rec0['check']}")
r2, rec2 = run(2)
check(r2 == 37, f"work(2) 返回 37=(10+2)*3+1 实际 {r2}")
check(rec2["printf"] == 1, f"work(2) printf 执行一次 实际 {rec2['printf']}")
check(rec2["check"] == [(THIS, 2)],
      f"work(2) mycheck 收到 (this, n=2) 实际 {rec2['check']}")

print("==" + (" 实例方法守卫全部通过 " if FAILS == 0 else f" {FAILS} 项失败 ") + "==")
sys.exit(1 if FAILS else 0)
