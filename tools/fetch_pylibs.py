#!/usr/bin/env python3
# 直接从 PyPI 下载 capstone/unicorn 的 win_amd64 wheel 并解压到 tools/pylibs
import json, os, sys, urllib.request, zipfile

DEST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pylibs")
os.makedirs(DEST, exist_ok=True)

def pick_wheel(pkg):
    with urllib.request.urlopen(f"https://pypi.org/pypi/{pkg}/json", timeout=60) as r:
        data = json.load(r)
    files = data["urls"]
    want = [f for f in files if f["filename"].endswith(".whl")
            and ("win_amd64" in f["filename"] or "win32" in f["filename"])]
    if not want:
        # fallback: 任意平台 wheel(纯 py)
        want = [f for f in files if f["filename"].endswith(".whl")]
    # 优先 py3-none / cp 版本匹配
    want.sort(key=lambda f: ("cp313" in f["filename"], "py3-none" in f["filename"],
                             f["filename"]), reverse=True)
    return want[0]

for pkg in ("capstone", "unicorn"):
    try:
        info = pick_wheel(pkg)
        url = info["url"]
        fn = info["filename"]
        print(f"[{pkg}] {fn}")
        local = os.path.join(DEST, fn)
        urllib.request.urlretrieve(url, local)
        with zipfile.ZipFile(local) as z:
            z.extractall(DEST)
        os.remove(local)
        print(f"[{pkg}] OK -> {DEST}")
    except Exception as e:
        print(f"[{pkg}] FAIL: {e}")
        sys.exit(1)
print("DONE")
