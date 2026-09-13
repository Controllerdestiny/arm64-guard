#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""最终验证:真实编译的 C 检查函数(只声明 2 个参数)经 trampoline 真实调用。
证明 check 只需声明目标函数实际参数个数。"""
import struct, sys
sys.path.insert(0, "tools")
import verify as V
import unicorn as U
from unicorn.arm64_const import *

data = open("build/libcheck.so", "rb").read()
# mycheck2 @ 模块 VA 0x4610,文件偏移 0x610(该 .so 偏移差 0x4000)
mc2 = data[0x610:0x610 + 12]
mc1 = data[0x61C:0x61C + 12]
assert len(mc2) == 12 and len(mc1) == 12, (len(mc2), len(mc1))
for i in V.md.disasm(mc2, V.CHECK_ADDR):
    print(f"mycheck2 -> {i.mnemonic} {i.op_str}")

dump = open("build/plan_dump_cpp.txt", encoding="utf-8", errors="replace").read()
plans = V.parse_plans(dump)
guard, patch, words, plen = plans[("block", "block")]
blob = b"".join(struct.pack("<I", w) for w in words)
tgt = open("build/libtarget_cpp.so", "rb").read()
segs = V.load_segments(tgt)
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
            uc.mem_write(base, tgt[so:so + sf])
    uc.mem_write(guard, patch)
    uc.mem_map(V.TRAMP_BASE, 0x1000, U.UC_PROT_ALL)
    uc.mem_write(V.TRAMP_BASE, blob)
    uc.mem_map(STACK, 0x10000, U.UC_PROT_ALL)
    uc.mem_map(V.CHECK_ADDR & ~0xFFF, 0x1000, U.UC_PROT_ALL)
    uc.mem_map(V.CALLEE_ADDR & ~0xFFF, 0x1000, U.UC_PROT_ALL)
    uc.mem_write(got, struct.pack("<Q", V.CALLEE_ADDR))
    uc.mem_map(THIS & ~0xFFF, 0x1000, U.UC_PROT_ALL)
    uc.mem_write(THIS, struct.pack("<i", 10))  # this->base = 10
    # 把真实编译的 mycheck2 字节放到 CHECK_ADDR —— trampoline 真实调用它,
    # 不再用 hook。它只读 x0/x1(声明了 2 个参数),多余寄存器参数被忽略。
    uc.mem_write(V.CHECK_ADDR, mc2)
    pfc = [0]
    def on_printf(u2, a2, s2, d2):
        pfc[0] += 1
        u2.reg_write(UC_ARM64_REG_PC, u2.reg_read(UC_ARM64_REG_X30))
    uc.hook_add(U.UC_HOOK_CODE, on_printf, None, V.CALLEE_ADDR, V.CALLEE_ADDR)
    uc.reg_write(UC_ARM64_REG_SP, STACK + 0x10000 - 0x100)
    uc.reg_write(UC_ARM64_REG_X0, THIS)
    uc.reg_write(UC_ARM64_REG_X1, n)
    uc.reg_write(UC_ARM64_REG_X30, 0x1)
    uc.hook_add(U.UC_HOOK_CODE, lambda u3, a3, s3, d3: u3.emu_stop(), None,
                0x1, 0x1)
    uc.emu_start(main_va, 0x1)
    return uc.reg_read(UC_ARM64_REG_X0), pfc[0]

FAILS = 0
def check(cond, name):
    global FAILS
    print(("  [PASS] " if cond else "  [FAIL] ") + name)
    if not cond:
        FAILS += 1

r0, p0 = run(0)
check(r0 == 10 and p0 == 0,
      f"work(0): 真实 mycheck2(声明2参数) 拒绝 -> ret={r0}(期望10) printf={p0}(期望0)")
r2, p2 = run(2)
check(r2 == 37 and p2 == 1,
      f"work(2): 真实 mycheck2 放行 -> ret={r2}(期望37) printf={p2}(期望1)")
print("==" + (" 真实 check 函数验证通过 " if FAILS == 0 else f" {FAILS} 项失败 ") + "==")
sys.exit(1 if FAILS else 0)
