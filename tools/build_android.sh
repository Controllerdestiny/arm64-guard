#!/bin/sh
# build_android.sh - 用 NDK 构建 Android arm64-v8a 产物
# 用法:ANDROID_NDK_HOME=/path/to/ndk ./tools/build_android.sh
set -e

NDK="${ANDROID_NDK_HOME:-$HOME/Android/Sdk/ndk/*}"
# 取最新 NDK
NDK=$(ls -d $NDK 2>/dev/null | sort -V | tail -1)
if [ -z "$NDK" ] || [ ! -d "$NDK" ]; then
  echo "NDK not found, set ANDROID_NDK_HOME" >&2; exit 1
fi
TC="$NDK/toolchains/llvm/prebuilt/$(uname -s | tr 'A-Z' 'a-z')-x86_64/bin"
CC="$TC/aarch64-linux-android24-clang"
[ -x "$CC" ] || CC="$TC/aarch64-linux-android24-clang.cmd"

mkdir -p build

SRCS="src/a64.c src/elf64.c src/analysis.c src/instr_plan.c src/instr.c"

echo "== engine =="
$CC -O2 -fPIC -shared $SRCS -Iinclude -Isrc -o build/libinstr.so

echo "== targets =="
$CC -O0 -fPIC -shared -fno-omit-frame-pointer demo/libtarget.c \
    -o build/libtarget.so
$CC -O0 -fPIC -shared -fno-omit-frame-pointer demo/libtarget_block.c \
    -o build/libtarget_block.so

echo "== demo =="
$CC -O2 demo/demo_main.c demo/mycheck.c $SRCS -Iinclude -Isrc \
    -ldl -llog -o build/demo_main

echo "done: build/{libinstr.so, libtarget.so, libtarget_block.so, demo_main}"
