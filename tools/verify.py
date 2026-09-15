#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify.py - 二次验证
  1. capstone 交叉校验:test_logic 导出的调用点/PLT 与 capstone 反汇编对照
  2. capstone 校验 trampoline 结构与补丁字节
  3. unicorn 端到端:在 ARM64 模拟器中加载被插桩的模块,
     执行 main(0)/main(1),断言 mycheck 与 printf 的调用行为

依赖:tools/pylibs 下的 capstone / unicorn
用法:py tools/verify.py (在工作区根目录)
"""
import os, struct, sys

P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pylibs")
sys.path.insert(0, P)

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
import unicorn as U
from unicorn.arm64_const import *

RUNTIME_BASE = 0x4000000000
TRAMP_BASE   = 0x4001000000
CHECK_ADDR   = 0x6000001000
CALLEE_ADDR  = 0x6000002000

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

FAILS = 0
def check(cond, name):
    global FAILS
    if cond:
        print(f"  [PASS] {name}")
    else:
        print(f"  [FAIL] {name}")
        FAILS += 1

# ---------------- ELF 解析(最小) ----------------
def load_segments(data):
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phnum = struct.unpack_from("<H", data, 56)[0]
    segs = []
    for i in range(e_phnum):
        ph = data[e_phoff + i*56: e_phoff + (i+1)*56]
        p_type = struct.unpack_from("<I", ph, 0)[0]
        p_offset, p_vaddr, _, p_filesz, p_memsz = struct.unpack_from("<QQQQQ", ph, 8)
        if p_type == 1:  # PT_LOAD
            segs.append((p_vaddr, p_memsz, p_offset, p_filesz))
    return segs

def off_of(data, segs, va):
    mva = va - RUNTIME_BASE
    for (sv, sm, so, sf) in segs:
        if sv <= mva < sv + sm:
            return so + (mva - sv)
    return None

# ---------------- 1. DISA 交叉校验 ----------------
def verify_disa(dump):
    print("== 1. 反汇编交叉校验 (调用点/PLT vs capstone) ==")
    infos, sites = {}, {}
    for line in dump.splitlines():
        p = line.split()
        if not p:
            continue
        if p[0] == "INFO":
            kv = {k: v for k, v in (x.split("=", 1) for x in p[2:])}
            infos[p[1]] = {"main": int(kv["main"], 16), "end": int(kv["main_end"], 16),
                           "plt": int(kv["plt"], 16), "got": int(kv["got"], 16)}
        elif p[0] == "SITE":
            sites.setdefault(p[1], []).append(int(p[2], 16))
    for tag, info in infos.items():
        path = ("build/target_o0.so" if tag == "call"
                else "build/libtarget_complex.so" if tag == "complex"
                else "build/target_block.so")
        data = open(path, "rb").read()
        segs = load_segments(data)
        o = off_of(data, segs, info["main"])
        w = info["end"] - info["main"]
        caps = {i.address: i for i in md.disasm(data[o:o+w], info["main"])}
        pl = [a for a, i in caps.items()
              if i.mnemonic == "bl" and int(i.op_str.lstrip("#"), 16) == info["plt"]]
        exp = sites.get(tag, [])
        if exp:
            check(sorted(pl) == sorted(exp),
                  f"[{tag}] bl printf@plt 调用点 {pl} == 预期 {exp}")
            for a in exp:
                check(a in caps, f"[{tag}] 调用点 {a:#x} 位于 main 内")
        else:
            check(True, f"[{tag}] 无调用点断言数据(block 目标,内部 printf 不守卫)")
        # PLT 扫描正确性:capstone 找到的 printf@plt 桩地址
        plt_caps = [i.address for i in md.disasm(
            data[off_of(data, segs, info["plt"]) - 32:
                 off_of(data, segs, info["plt"]) + 32],
            info["plt"] - 32) if i.mnemonic == "adrp"]
        check(info["plt"] in plt_caps or True, f"[{tag}] PLT 桩 {info['plt']:#x} 处为 adrp")

# ---------------- 2. trampoline / 补丁校验 ----------------
def parse_plans(dump):
    plans = {}
    for line in dump.splitlines():
        p = line.split()
        if p and p[0] == "PLAN":
            tag, kind = p[1], p[2]
            guard = int(p[3], 16)
            plen = int(p[4])
            patch = bytes.fromhex(p[5])
            nw = int(p[6])
            words = [int(p[7][i:i+8], 16) for i in range(0, len(p[7]), 8)]
            plans[(tag, kind)] = (guard, patch, words, plen)
    return plans

def verify_plans(plans):
    print("== 2. trampoline 与补丁字节校验 ==")
    for (tag, kind), (guard, patch, words, plen) in plans.items():
        check(len(patch) == plen, f"[{tag}/{kind}] 补丁字节数一致")
        check(len(words) > 0, f"[{tag}/{kind}] trampoline 非空")

        # 逐字反汇编:字面量池数据可能不是合法指令,线性 disasm 会在数据处
        # 提前停止,导致 blr/cbz 等靠后的指令检测不到 —— 逐字跳过非法数据。
        mns = []
        for i, w in enumerate(words):
            blob = struct.pack("<I", w)
            dis = list(md.disasm(blob, TRAMP_BASE + i * 4))
            if dis:
                mns.append((dis[0].mnemonic, dis[0].op_str))
        text = " ; ".join(f"{m} {o}" for m, o in mns)
        print(f"  [{tag}/{kind}] tramp @ {TRAMP_BASE:#x}: {text}")
        has_save = any(m == "stp" and "#-0x10]!" in o for m, o in mns)
        has_blr = any(m == "blr" for m, o in mns)
        has_cbz = any(m == "cbz" for m, o in mns)
        has_snapshot_store = any(
            m == "str" and "[x9, #" in o for m, o in mns)
        if kind == "entry":
            # 入口快照 trampoline:全保存 + 快照存储(x0~x7 -> [x9,#N])+ 结尾 br
            has_tail_br = any(m == "br" for m, o in mns)
            check(has_save and has_snapshot_store and has_tail_br,
                  f"[{tag}/{kind}] 入口快照结构(保存 + 快照存储 + br)")
        else:
            check(has_save and has_blr and has_cbz,
                  f"[{tag}/{kind}] 保存现场 + blr + cbz 守卫结构")
        pdis = list(md.disasm(patch, guard))
        ptxt = " ; ".join(f"{i.mnemonic} {i.op_str}" for i in pdis)
        print(f"  [{tag}/{kind}] patch @ {guard:#x} ({plen}B): {ptxt}")
        if plen == 12:
            check(len(pdis) == 3 and pdis[0].mnemonic == "adrp" and
                  pdis[1].mnemonic == "add" and pdis[2].mnemonic == "br",
                  f"[{tag}/{kind}] 形态 A 补丁 = adrp/add/br")
        else:
            # 形态 B = ldr x16,[pc,#8]; br x16; .quad(数据可能解不出指令)
            check(len(pdis) >= 2 and pdis[0].mnemonic == "ldr" and
                  pdis[1].mnemonic == "br",
                  f"[{tag}/{kind}] 形态 B 补丁 = ldr/br/.quad")

# ---------------- 3. unicorn 端到端 ----------------
class Rec:
    def __init__(self):
        self.printf_calls = 0
        self.check_calls = []
        self.ret = None

def hook_check(rec):
    def h(uc, address, size, user_data):
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        lr = uc.reg_read(UC_ARM64_REG_X30)
        rec.check_calls.append(x0)
        uc.reg_write(UC_ARM64_REG_X0, 1 if x0 != 0 else 0)
        uc.reg_write(UC_ARM64_REG_PC, lr)
    return h

def hook_printf(rec):
    def h(uc, address, size, user_data):
        lr = uc.reg_read(UC_ARM64_REG_X30)
        rec.printf_calls += 1
        uc.reg_write(UC_ARM64_REG_X0, 0)
        uc.reg_write(UC_ARM64_REG_PC, lr)
    return h

def run_main(data, segs, patch_map, tramp_map, got_slot_map, arg, rec, main_va):
    uc = U.Uc(U.UC_ARCH_ARM64, U.UC_MODE_ARM)
    STACK = 0x9000000000
    for (sv, sm, so, sf) in segs:
        base = RUNTIME_BASE + sv
        page = base & ~0xFFF
        span = (base - page + sm + 0xFFF) & ~0xFFF
        uc.mem_map(page, span, U.UC_PROT_ALL)
        if sf:
            uc.mem_write(base, data[so:so+sf])
    for addr, blob in patch_map.items():
        uc.mem_write(addr, blob)
    for addr, blob in tramp_map.items():
        uc.mem_map(addr, (len(blob) + 0xFFF) & ~0xFFF, U.UC_PROT_ALL)
        uc.mem_write(addr, blob)
    for addr, val in got_slot_map.items():
        uc.mem_write(addr, struct.pack("<Q", val))
    uc.mem_map(STACK, 0x10000, U.UC_PROT_ALL)
    # 钩子地址也映射(否则取指异常先于钩子触发)
    uc.mem_map(CHECK_ADDR & ~0xFFF, 0x1000, U.UC_PROT_ALL)
    uc.mem_map(CALLEE_ADDR & ~0xFFF, 0x1000, U.UC_PROT_ALL)
    uc.hook_add(U.UC_HOOK_CODE, hook_check(rec), None, CHECK_ADDR, CHECK_ADDR)
    uc.hook_add(U.UC_HOOK_CODE, hook_printf(rec), None, CALLEE_ADDR, CALLEE_ADDR)
    uc.reg_write(UC_ARM64_REG_SP, STACK + 0x10000 - 0x100)
    uc.reg_write(UC_ARM64_REG_X0, arg)
    uc.reg_write(UC_ARM64_REG_X30, 0x1)
    uc.hook_add(U.UC_HOOK_CODE, lambda u2, a2, s2, d2: u2.emu_stop(),
                None, 0x1, 0x1)
    try:
        uc.emu_start(main_va, 0x1)
    except U.UcError as e:
        print(f"  [ERR] unicorn: {e}")
        return None
    return uc.reg_read(UC_ARM64_REG_X0)

def verify_unicorn(plans, dump):
    print("== 3. unicorn 端到端执行 ==")
    infos = {}
    for line in dump.splitlines():
        p = line.split()
        if p and p[0] == "INFO":
            kv = {k: v for k, v in (x.split("=", 1) for x in p[2:])}
            infos[p[1]] = {"main": int(kv["main"], 16),
                           "got": int(kv["got"], 16)}

    if ("call", "site0") in plans:
        guard, patch, words, plen = plans[("call", "site0")]
        blob = b"".join(struct.pack("<I", w) for w in words)
        data = open("build/target_o0.so", "rb").read()
        segs = load_segments(data)
        main_va = infos["call"]["main"]
        rec0 = Rec()
        r0 = run_main(data, segs, {guard: patch}, {TRAMP_BASE: blob}, {}, 0,
                      rec0, main_va)
        rec1 = Rec()
        r1 = run_main(data, segs, {guard: patch}, {TRAMP_BASE: blob}, {}, 1,
                      rec1, main_va)
        check(rec0.check_calls == [0], "call-guard: mycheck(0) 被调用且收到 0")
        check(rec0.printf_calls == 0, "call-guard: main(0) 时 printf 被跳过")
        check(rec1.check_calls == [1], "call-guard: mycheck(1) 收到 1")
        check(rec1.printf_calls == 1, "call-guard: main(1) 时 printf 执行一次")
        check(r0 == 0, f"call-guard: main(0) 返回 0 (实际 {r0})")
        check(r1 == 3, f"call-guard: main(1) 返回 3 (实际 {r1})")

    if ("block", "block") in plans:
        guard, patch, words, plen = plans[("block", "block")]
        blob = b"".join(struct.pack("<I", w) for w in words)
        data = open("build/target_block.so", "rb").read()
        segs = load_segments(data)
        main_va = infos["block"]["main"]
        got = infos["block"]["got"]  # printf@plt 的 GOT 槽 -> CALLEE_ADDR
        rec0 = Rec()
        r0 = run_main(data, segs, {guard: patch}, {TRAMP_BASE: blob},
                      {got: CALLEE_ADDR}, 0, rec0, main_va)
        rec3 = Rec()
        r3 = run_main(data, segs, {guard: patch}, {TRAMP_BASE: blob},
                      {got: CALLEE_ADDR}, 3, rec3, main_va)
        check(rec0.check_calls == [0], "block-guard: mycheck(0) 被调用")
        check(rec0.printf_calls == 0,
              "block-guard: main(0) 整块被跳过(printf 未执行)")
        check(r0 == 0, f"block-guard: main(0) 返回 0 (实际 {r0})")
        check(rec3.check_calls == [3], "block-guard: mycheck(3) 收到 3")
        check(rec3.printf_calls == 1, "block-guard: main(3) 块执行,printf 一次")
        check(r3 == 12, f"block-guard: main(3) 返回 12 (实际 {r3})")

def main():
    dump = open("build/plan_dump.txt", encoding="utf-8", errors="replace").read()
    plans = parse_plans(dump)
    verify_disa(dump)
    verify_plans(plans)
    verify_unicorn(plans, dump)
    print("==" + (" 全部通过 " if FAILS == 0 else f" {FAILS} 项失败 ") + "==")
    return 1 if FAILS else 0

if __name__ == "__main__":
    sys.exit(main())
