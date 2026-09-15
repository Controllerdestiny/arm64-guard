# build.ps1 - build demo/target/test artifacts
# usage: powershell -ExecutionPolicy Bypass -File tools/build.ps1
$ErrorActionPreference = "Stop"

$NDK = if ($env:ANDROID_NDK_HOME) { $env:ANDROID_NDK_HOME } else { "D:\SDK\ndk\28.2.13676358" }
$TC  = "$NDK\toolchains\llvm\prebuilt\windows-x86_64\bin"
$CC  = "$TC\aarch64-linux-android24-clang.cmd"
$ZIG = Join-Path $PSScriptRoot "zig\current\zig.exe"

if (!(Test-Path $CC))  { throw "NDK clang not found: $CC" }
if (!(Test-Path $ZIG)) { throw "zig not found: $ZIG" }

# zig cache inside workspace (sandbox-friendly)
$env:ZIG_GLOBAL_CACHE_DIR = Join-Path $PWD ".zig-global"
$env:ZIG_LOCAL_CACHE_DIR  = Join-Path $PWD ".zig-local"
New-Item -ItemType Directory -Force -Path $env:ZIG_GLOBAL_CACHE_DIR, $env:ZIG_LOCAL_CACHE_DIR | Out-Null

New-Item -ItemType Directory -Force -Path "build" | Out-Null

Write-Host "== 1. cross-compile ARM64 target .so (NDK) =="
& $CC -O0 -fPIC -shared -fno-omit-frame-pointer demo/libtarget.c       -o build/target_o0.so
& $CC -O2 -fPIC -shared                       demo/libtarget.c       -o build/target_o2.so
& $CC -O0 -fPIC -shared -fno-omit-frame-pointer demo/libtarget_block.c -o build/target_block.so
& $CC -O0 -fPIC -shared -fno-omit-frame-pointer demo/libtarget_block.c -o build/libtarget_block.so
& $CC -O0 -fPIC -shared -fno-omit-frame-pointer demo/libtarget_complex.c -o build/libtarget_complex.so
$CXX = "$TC\aarch64-linux-android24-clang++.cmd"
& $CXX -O0 -fPIC -shared -fno-omit-frame-pointer demo/libtarget_cpp.cpp -o build/libtarget_cpp.so
& $CC -O2 -fPIC -shared demo/libcheck.c -o build/libcheck.so

Write-Host "== 2. build Android engine + demo =="
$SRCS = @("src/a64.c", "src/elf64.c", "src/analysis.c", "src/instr_plan.c", "src/instr.c")
& $CC -O2 -fPIC -shared @SRCS -Iinclude -Isrc -o build/libinstr.so
& $CC -O2 demo/demo_main.c demo/mycheck.c @SRCS -Iinclude -Isrc -ldl -llog -o build/demo_main

Write-Host "== 3. build host logic test (zig) =="
& $ZIG cc -target x86_64-windows-gnu -O2 tests/test_logic.c src/a64.c src/elf64.c src/analysis.c src/instr_plan.c -Isrc -Iinclude -o build/test_logic.exe
if ($LASTEXITCODE -ne 0) { throw "zig build failed" }

Write-Host "== 4. run host logic test =="
& ".\build\test_logic.exe" ".\build\target_o0.so" ".\build\target_block.so" ".\build\plan_dump.txt" "main" ".\build\libtarget_complex.so"
Write-Host "exit: $LASTEXITCODE"

Write-Host "== 5. C++ 实例方法逻辑测试 =="
& ".\build\test_logic.exe" ".\build\libtarget_cpp.so" ".\build\libtarget_cpp.so" ".\build\plan_dump_cpp.txt" "_ZN3Foo4workEi"
Write-Host "exit: $LASTEXITCODE"
