#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""入口快照模式验证(unicorn 端到端):
  1. 把入口快照补丁(入口 trampoline 保存 x0~x7 到快照区)+ 快照模式守卫补丁
     同时应用到 target_block.so 的 main;
  2. 执行 main(argc):断言 check 收到的 a0 与入口 argc **完全一致**,
     且放行/拒绝两条路径的 printf 次数与返回值正确。
  这证明:即使不做数据流分析,快照模式也能 100% 恢复入口参数。"""
import struct, sys
sys.path.insert(0, "tools")
import verify as V
import unicorn as U
from unicorn.arm64_const import *

DUMP = "build/plan_dump.txt"
TARGET = "build/target_block.so"

SNAP = V.TRAMP_BASE + 0x1000     # 快照区(与 test_logic 的规划一致)
ETRAMP = V.TRAMP_BASE + 0x2000   # 入口 trampoline

dump = open(DUMP, encoding="utf-8", errors="replace").read()
plans = V.parse_plans(dump)
need = ("block", "entry"), ("block", "snapsnap"), ("block", "block")
for key in need:
    if key not in plans:
        print(f"[FAIL] dump 缺少 {key} 计划")
        sys.exit(1)

eaddr, epatch, ewords, eplen = plans[("block", "entry")]
gaddr, gpatch, gwords, gplen = plans[("block", "snapsnap")]
baddr, bpatch, bwords, bplen = plans[("block", "block")]

eblob = b"".join(struct.pack("<I", w) for w in ewords)
gblob = b"".join(struct.pack("<I", w) for w in gwords)
print(f"entry patch @ {eaddr:#x} ({eplen}B) -> {ETRAMP:#x}")
print(f"guard patch @ {gaddr:#x} ({gplen}B) -> {V.TRAMP_BASE:#x}")

infos = {}
for line in dump.splitlines():
    p = line.split()
    if p and p[0] == "INFO":
        kv = {k: v for k, v in (x.split("=", 1) for x in p[2:])}
        infos[p[1]] = kv
main_va = int(infos["block"]["main"], 16)
got = int(infos["block"]["got"], 16)

data = open(TARGET, "rb").read()
segs = V.load_segments(data)

def run(argc):
    uc = U.Uc(U.UC_ARCH_ARM64, U.UC_MODE_ARM)
    STACK = 0x9000000000
    for (sv, sm, so, sf) in segs:
        base = V.RUNTIME_BASE + sv
        page = base & ~0xFFF
        span = (base - page + sm + 0xFFF) & ~0xFFF
        uc.mem_map(page, span, U.UC_PROT_ALL)
        if sf:
            uc.mem_write(base, data[so:so + sf])
    uc.mem_write(eaddr, epatch)          # 入口补丁
    uc.mem_write(gaddr, gpatch)          # 守卫补丁
    uc.mem_map(V.TRAMP_BASE, 0x4000, U.UC_PROT_ALL)   # 覆盖 guard tramp + 快照 + 入口 tramp
    uc.mem_write(V.TRAMP_BASE, gblob)    # 守卫 trampoline(读快照区)
    uc.mem_write(ETRAMP, eblob)          # 入口 trampoline(写快照区)
    uc.mem_map(STACK, 0x10000, U.UC_PROT_ALL)
    uc.mem_map(V.CHECK_ADDR & ~0xFFF, 0x1000, U.UC_PROT_ALL)
    uc.mem_map(V.CALLEE_ADDR & ~0xFFF, 0x1000, U.UC_PROT_ALL)
    uc.mem_write(got, struct.pack("<Q", V.CALLEE_ADDR))
    rec = {"check": [], "printf": 0}

    def on_check(u2, a2, s2, d2):
        rec["check"].append(u2.reg_read(UC_ARM64_REG_X0))
        u2.reg_write(UC_ARM64_REG_X0, 1 if argc != 0 else 0)
        u2.reg_write(UC_ARM64_REG_PC, u2.reg_read(UC_ARM64_REG_X30))

    def on_printf(u2, a2, s2, d2):
        rec["printf"] += 1
        u2.reg_write(UC_ARM64_REG_PC, u2.reg_read(UC_ARM64_REG_X30))

    uc.hook_add(U.UC_HOOK_CODE, on_check, None, V.CHECK_ADDR, V.CHECK_ADDR)
    uc.hook_add(U.UC_HOOK_CODE, on_printf, None, V.CALLEE_ADDR, V.CALLEE_ADDR)
    uc.reg_write(UC_ARM64_REG_SP, STACK + 0x10000 - 0x100)
    uc.reg_write(UC_ARM64_REG_X0, argc)
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
check(rec0["check"] == [0], f"main(0):check 收到入口 argc=0(快照) 实际 {rec0['check']}")
check(rec0["printf"] == 0, f"main(0):printf 未执行(整块跳过) 实际 {rec0['printf']}")
check(r0 == 0, f"main(0):返回 0 实际 {r0}")

r3, rec3 = run(3)
check(rec3["check"] == [3], f"main(3):check 收到入口 argc=3(快照) 实际 {rec3['check']}")
check(rec3["printf"] == 1, f"main(3):printf 执行一次 实际 {rec3['printf']}")
check(r3 == 12, f"main(3):返回 12 实际 {r3}")

print("==" + (" 入口快照模式全部通过 " if FAILS == 0 else f" {FAILS} 项失败 ") + "==")
sys.exit(1 if FAILS else 0)
