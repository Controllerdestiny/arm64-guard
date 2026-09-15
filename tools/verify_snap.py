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
need = ("block", "entry"), ("block", "entrychain"), ("block", "snapsnap")
for key in need:
    if key not in plans:
        print(f"[FAIL] dump 缺少 {key} 计划")
        sys.exit(1)

eaddr, epatch, ewords, eplen = plans[("block", "entry")]
echain, ecpatch, ecwords, ecplen = plans[("block", "entrychain")]
gaddr, gpatch, gwords, gplen = plans[("block", "snapsnap")]
baddr, bpatch, bwords, bplen = plans[("block", "block")]

eblob = b"".join(struct.pack("<I", w) for w in ewords)
ecblob = b"".join(struct.pack("<I", w) for w in ecwords)
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

# ---------------- 链式共存:Dobby 先 hook 入口,快照模式链在其上 ----------------
# 模拟一个"已安装的 Dobby":入口被改写成 ldr/br/.quad 跳到 DOBBY_TRAMP,
# DOBBY_TRAMP 里是"重放原始入口指令 + 跳回 fn+16"(真实 Dobby trampoline 的
# 简化)。随后安装我们的快照守卫:入口补丁覆盖 Dobby 的补丁,但链式入口
# trampoline 保存参数后直接跳进 DOBBY_TRAMP —— 两条 hook 同时生效。
DOBBY_TRAMP = V.TRAMP_BASE + 0x3000   # 与 test_logic 规划的 prev_hook 一致
CTRAMP = V.TRAMP_BASE + 0x2000        # 链式入口 trampoline(entrychain 计划)

# 从镜像读 main 原始入口 16 字节(stp/sub 等,非 PC 相对,可原样搬移)
def entry_bytes(data, segs, va):
    mva = va - V.RUNTIME_BASE
    for (sv, sm, so, sf) in segs:
        if sv <= mva < sv + sm:
            return data[so + (mva - sv): so + (mva - sv) + 16]
    return None
orig16 = entry_bytes(data, segs, main_va)
assert orig16 and len(orig16) == 16, "读取 main 原始入口字节失败"

def run_chained(argc):
    uc = U.Uc(U.UC_ARCH_ARM64, U.UC_MODE_ARM)
    STACK = 0x9000000000
    for (sv, sm, so, sf) in segs:
        base = V.RUNTIME_BASE + sv
        page = base & ~0xFFF
        span = (base - page + sm + 0xFFF) & ~0xFFF
        uc.mem_map(page, span, U.UC_PROT_ALL)
        if sf:
            uc.mem_write(base, data[so:so + sf])
    # 1) 模拟 Dobby 已安装:入口补丁 + Dobby trampoline(原样重放入口 + 跳回 fn+16)
    dpat = struct.pack("<I", 0x58000050) + struct.pack("<I", 0xD61F0200) + \
           struct.pack("<Q", DOBBY_TRAMP)
    uc.mem_write(main_va, dpat)
    dobby_body = orig16 + struct.pack("<I", 0x14000000 | (((main_va + 16 - DOBBY_TRAMP - len(orig16)) >> 2) & 0x3FFFFFF))
    uc.mem_map(V.TRAMP_BASE, 0x4000, U.UC_PROT_ALL)   # 覆盖 guard tramp + 快照 + 链式入口 tramp + Dobby tramp
    uc.mem_write(DOBBY_TRAMP, dobby_body)
    # 2) 再装我们的快照守卫:入口补丁(覆盖 Dobby 补丁)+ 链式入口 trampoline + 守卫
    uc.mem_write(main_va, ecpatch)            # 我们的入口补丁(entrychain)
    uc.mem_write(CTRAMP, ecblob)              # 链式入口 trampoline
    uc.mem_write(gaddr, gpatch)               # 守卫补丁
    uc.mem_write(V.TRAMP_BASE, gblob)         # 守卫 trampoline
    uc.mem_map(STACK, 0x10000, U.UC_PROT_ALL)
    uc.mem_map(V.CHECK_ADDR & ~0xFFF, 0x1000, U.UC_PROT_ALL)
    uc.mem_map(V.CALLEE_ADDR & ~0xFFF, 0x1000, U.UC_PROT_ALL)
    uc.mem_write(got, struct.pack("<Q", V.CALLEE_ADDR))
    rec = {"check": [], "printf": 0, "dobby": 0}
    def on_dobby(u2, a2, s2, d2):
        rec["dobby"] += 1                      # Dobby trampoline 被执行
    def on_check(u2, a2, s2, d2):
        rec["check"].append(u2.reg_read(UC_ARM64_REG_X0))
        u2.reg_write(UC_ARM64_REG_X0, 1 if argc != 0 else 0)
        u2.reg_write(UC_ARM64_REG_PC, u2.reg_read(UC_ARM64_REG_X30))
    def on_printf(u2, a2, s2, d2):
        rec["printf"] += 1
        u2.reg_write(UC_ARM64_REG_PC, u2.reg_read(UC_ARM64_REG_X30))
    uc.hook_add(U.UC_HOOK_CODE, on_dobby, None, DOBBY_TRAMP, DOBBY_TRAMP)
    uc.hook_add(U.UC_HOOK_CODE, on_check, None, V.CHECK_ADDR, V.CHECK_ADDR)
    uc.hook_add(U.UC_HOOK_CODE, on_printf, None, V.CALLEE_ADDR, V.CALLEE_ADDR)
    uc.reg_write(UC_ARM64_REG_SP, STACK + 0x10000 - 0x100)
    uc.reg_write(UC_ARM64_REG_X0, argc)
    uc.reg_write(UC_ARM64_REG_X30, 0x1)
    uc.hook_add(U.UC_HOOK_CODE, lambda u3, a3, s3, d3: u3.emu_stop(), None,
                0x1, 0x1)
    uc.emu_start(main_va, 0x1)
    return uc.reg_read(UC_ARM64_REG_X0), rec

print("-- 链式共存:Dobby 先 hook,快照守卫链在其上 --")
rc3, cr3 = run_chained(3)
check(cr3["dobby"] == 1, f"链式:Dobby trampoline 被执行(两条 hook 共存) 实际 {cr3['dobby']}")
check(cr3["check"] == [3], f"链式:check 收到入口 argc=3(快照) 实际 {cr3['check']}")
check(cr3["printf"] == 1, f"链式:printf 执行一次 实际 {cr3['printf']}")
check(rc3 == 12, f"链式:返回 12 实际 {rc3}")

print("==" + (" 入口快照模式(含 Dobby 链式共存)全部通过 " if FAILS == 0
              else f" {FAILS} 项失败 ") + "==")
sys.exit(1 if FAILS else 0)
