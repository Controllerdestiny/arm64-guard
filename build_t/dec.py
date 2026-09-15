import sys

def sext(v, bits):
    s = v & ((1<<bits)-1)
    if s & (1<<(bits-1)): s -= (1<<bits)
    return s

def dec(addr, w):
    op = []
    # b / bl
    if (w & 0xFC000000) == 0x14000000:
        imm = sext(w & 0x3FFFFFF, 26) * 4
        return f"b  #{addr+imm:#x}"
    if (w & 0xFC000000) == 0x94000000:
        imm = sext(w & 0x3FFFFFF, 26) * 4
        return f"bl #{addr+imm:#x}"
    # br/blr/ret
    if (w & 0xFFFFFC1F) == 0xD61F0000: return f"br x{w&31}"
    if (w & 0xFFFFFC1F) == 0xD63F0000: return f"blr x{w&31}"
    if (w & 0xFFFFFC1F) == 0xD65F0000: return f"ret"
    # cbz/cbnz
    if (w & 0x7E000000) in (0x34000000, 0xB4000000, 0x35000000, 0xB5000000):
        cbnz = (w & 0x7E000000) in (0x35000000, 0xB5000000)
        imm = sext((w >> 5) & 0x7FFFF, 19) * 4
        nm = "cbnz" if cbnz else "cbz"
        return f"{nm} w{w&31}, #{addr+imm:#x}"
    # tbz/tbnz
    if (w & 0x7E000000) in (0x36000000,0xB6000000,0x37000000,0xB7000000):
        imm = sext((w >> 5) & 0x3FFF, 14) * 4
        b5 = (w >> 31) & 1; b40 = (w >> 19) & 0x1F
        return f"tbz/tbnz w{w&31}, #{b5*32+b40}, #{addr+imm:#x}"
    # adr/adrp
    if (w & 0x1F000000) == 0x10000000:
        immlo = (w >> 29) & 3; immhi = sext((w >> 5) & 0x7FFFF, 19)
        imm = (immhi << 2) | immlo
        if w & 0x80000000:
            return f"adrp x{w&31}, #{((addr & ~0xFFF) + imm*4096):#x}"
        return f"adr x{w&31}, #{addr+imm:#x}"
    # ldr literal
    if (w & 0xFF000000) in (0x18000000, 0x58000000, 0x98000000):
        imm = sext((w >> 5) & 0x7FFFF, 19) * 4
        return f"ldr x{w&31}, [{addr+imm:#x}]"
    # mrs/msr
    if (w & 0xFFF00000) == 0xD5300000: return f"mrs x{w&31}, nzcv"
    if (w & 0xFFF00000) == 0xD5100000: return f"msr nzcv, x{w&31}"
    # mov (orr register)
    if ((w & 0x7F000000) == 0x2A000000 or (w & 0x7F000000) == 0xAA000000) and (w & 0x00E00000)==0 and (w & 0x0000FC00)==0:
        rn=(w>>5)&31; rm=(w>>16)&31
        if rn==31 or rm==31:
            return f"mov x{w&31}, x{rm if rm!=31 else rn}"
    # add/sub imm
    for (base, nm) in ((0x91000000,"add"),(0xD1000000,"sub"),(0x11000000,"add"),(0x51000000,"sub")):
        if (w & 0xFF800000) == base:
            imm = (w >> 10) & 0xFFF
            return f"{nm} x{w&31}, x{(w>>5)&31}, #{imm}"
    # stp/ldp pre/post
    for (mask, base, nm, post) in ((0x7FC00000,0xA9800000,"stp",False),(0x7FC00000,0xA8800000,"stp",True),(0x7FC00000,0xA9C00000,"ldp",False),(0x7FC00000,0xA8C00000,"ldp",True),(0x7FC00000,0x29800000,"stp",False),(0x7FC00000,0x28800000,"stp",True),(0x7FC00000,0x29C00000,"ldp",False),(0x7FC00000,0x28C00000,"ldp",True)):
        if (w & mask) == base:
            rt=w&31; rt2=(w>>10)&31; rn=(w>>5)&31
            imm = sext((w>>15)&0x7F,7)*8
            if post: return f"{nm} x{rt}, x{rt2}, [x{rn}], #{imm}"
            return f"{nm} x{rt}, x{rt2}, [x{rn}, #{imm}]!"
    # str/ldr imm unsigned
    if (w & 0xFFC00000) == 0xF9000000:
        return f"str x{w&31}, [x{(w>>5)&31}, #{((w>>10)&0xFFF)*8}]"
    if (w & 0xFFC00000) == 0xF9400000:
        return f"ldr x{w&31}, [x{(w>>5)&31}, #{((w>>10)&0xFFF)*8}]"
    if (w & 0xFFC00000) == 0xB9000000:
        return f"str w{w&31}, [x{(w>>5)&31}, #{((w>>10)&0xFFF)*4}]"
    if (w & 0xFFC00000) == 0xB9400000:
        return f"ldr w{w&31}, [x{(w>>5)&31}, #{((w>>10)&0xFFF)*4}]"
    # str/ldr unscaled/pre/post
    if (w & 0x3F200000) == 0x38000000:
        mode=(w>>10)&3; imm=sext((w>>12)&0x1FF,9)
        rt=w&31; rn=(w>>5)&31
        ldr = (w>>22)&3 == 1
        nm = "ldr" if ldr else "str"
        if mode==1: return f"{nm} x{rt}, [x{rn}], #{imm}"
        if mode==3: return f"{nm} x{rt}, [x{rn}, #{imm}]!"
        return f"{nm} x{rt}, [x{rn}, #{imm}]"
    return f".word 0x{w:08x}"

addr = 0x4001000000  # placeholder base
data = bytes.fromhex(sys.argv[1])
for i in range(0, len(data), 4):
    w = int.from_bytes(data[i:i+4], 'little')
    print(f"  {addr+i:08x}: {dec(addr+i, w)}")
