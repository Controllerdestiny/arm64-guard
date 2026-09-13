#!/usr/bin/env python3
# 下载 zig 到 tools/zig/ 下(用于宿主机编译 C 测试程序)
import json, os, sys, urllib.request, zipfile, shutil

DEST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zig")
os.makedirs(DEST, exist_ok=True)

with urllib.request.urlopen("https://ziglang.org/download/index.json", timeout=60) as r:
    data = json.load(r)

# 找最新 stable 版本
version = None
for v in data:
    if "stable" not in data[v]:
        continue
    version = v
    break
if not version:
    # 退而求其次:第一个带 windows 的版本
    for v in data:
        if "x86_64-windows" in data[v]:
            version = v
            break
if not version:
    print("no zig version found")
    sys.exit(1)

info = data[version]
win = info.get("x86_64-windows")
if not win:
    print(f"no windows build for {version}")
    sys.exit(1)
url = win["tarball"]
fn = url.split("/")[-1]
print(f"[zig] {version} {fn} ({win.get('size', '?')} bytes)")
local = os.path.join(DEST, fn)
urllib.request.urlretrieve(url, local)
print("[zig] downloaded, extracting...")
with zipfile.ZipFile(local) as z:
    z.extractall(DEST)
os.remove(local)
# 把解压目录改名为 zig-ver
for name in os.listdir(DEST):
    full = os.path.join(DEST, name)
    if os.path.isdir(full) and name.startswith("zig-"):
        target = os.path.join(DEST, "current")
        if os.path.exists(target):
            shutil.rmtree(target)
        os.rename(full, target)
        break
print("[zig] OK ->", os.path.join(DEST, "current", "zig.exe"))
