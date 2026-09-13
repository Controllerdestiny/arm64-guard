# arm64-guard

AArch64 (ARM64) 运行时插桩库:在目标函数内部任意代码块入口注入一个运行时守卫,
把代码块变成条件执行——**这不是 hook**(不改函数入口、不劫持 GOT/PLT),
而是在指定位置改写指令、插入"检查函数 + 代码块"的结构。

```c
// 插桩前                                   // 插桩后(运行时完成)
int fn(int i) {                             int fn(int i) {
    // 其他逻辑                                  // 其他逻辑
    <代码块>                  ==>               if (mycheck(i)) { <代码块> }
    // 其他逻辑                                  // 其他逻辑
}                                           }
```

- 平台:AArch64 / Android (NDK)、Linux aarch64,小端 ELF
- 一行 API、一个头文件、dobby 式用法
- 检查函数自动收到目标函数**入口**的 x0~x7(实例方法天然支持:`a0 = this`)
- 无需 dlopen 句柄 / 符号表:`dladdr` 自动定位函数所在模块

## 特性

- **代码块守卫**:`if (check(入口参数)) { [start, end) }`,不满足条件整块跳过;
  块内的循环、分支、函数调用原样执行/跳过,块入口寄存器输入(x0-x7)完整保留
- **调用点守卫**(引擎内部能力):守卫对某函数的所有调用
- **多参数默认**:数据流分析自动恢复目标函数入口的 x0~x7,按 AArch64 调用约定
  传给 check;check 只需声明目标函数实际有的参数个数(最多 8 个,多余的寄存器参数被忽略)
- **实例方法支持**:C++ 成员函数入口参数 `a0=this, a1=第一个显式参数, ...`,
  与 hook 框架的替换函数约定一致
- **大函数支持**:目标函数上限 1M 条指令(约 4MB 代码),实测 92 万字节函数正常插桩
- **完全位置无关的 trampoline**:所有绝对地址经内联字面量池,无距离限制
- **可卸载**:恢复原指令并释放 trampoline
- **安全**:补丁前分析失败、范围非法、重定位不支持等均返回错误码而非越界

## 工作原理

1. **参数存活位置分析**(无需调试信息):从函数入口做前向必经数据流分析,
   确定入口参数 x0~x7 中每一个在守卫点处的存活位置(寄存器或栈槽
   `[x29/#sp, #off]`),处理 `mov` 拷贝、`str/stp` 压栈、`add x29, sp` 帧基换算、
   `bl` 清除 caller-saved 等。
2. **补丁**:在守卫点改写 12 或 16 字节跳转到 trampoline
   (形态 A:`adrp/add/br`,距守卫 <4GB;形态 B:`ldr/br/.quad`,无距离限制)。
   被覆盖的原指令搬移进 trampoline 重放;若其中含有指向补丁区的分支
   (如循环跳回),目标会被重映射到该指令在 trampoline 里的新地址。
3. **trampoline**:保存现场(x0-x7 / NZCV / x30)→ 恢复入口参数到 x0-x7 →
   调用 check → 通过则重放被搬移指令并继续;拒绝则直接跳到代码块末尾。

## 快速开始

```c
#include "instr.h"

/* 检查函数:按目标函数"入口"的 x0~x7 收到其参数。
 * 只需声明目标函数实际有的参数个数,多余的寄存器参数被忽略。
 *   普通函数      a0 = 第一个参数
 *   C++ 实例方法 a0 = this,a1 = 第一个显式参数
 * 返回 0 跳过目标代码,非 0 放行。
 * 例:目标函数 Foo::work(int n),所以只声明 2 个参数 */
int mycheck(int64_t a0, int64_t a1) {
    return a1 != 0;
}

/* 在初始化入口调用(init 数组 / JNI_OnLoad / 业务初始化) */
void install_guard(void *fn, void *block_start, void *block_end) {
    if (instr_guard_block(fn, block_start, block_end, (void *)mycheck) != INSTR_OK)
        log_error("%s", instr_last_error());
}
```

`fn` 可以是 `dlsym` / vtable / 偏移得到的任意函数地址。
`block_start` / `block_end` 的获取方式:

- 目标由自己编译:在源码里用两个内联汇编标记夹住代码块,运行时扫描标记
  (参考 `demo/libtarget_block.c` 与 `demo/demo_main.c` 的 `find_block`);
- 目标为他人 so:用 `llvm-objdump -d` / `addr2line` 反汇编,挑出代码块首尾地址
  (要求 `block_end - block_start >= 12 字节`,建议留更大余量)。

## API

公共 API 仅 3 个:

```c
/* 唯一主 API:守卫 fn 内 [block_start, block_end) 的代码块。
 * check 为任意签名的函数指针(传 (void*)check 即可)。调用时按 AArch64
 * 调用约定把目标函数"入口"的 x0~x7 传给它(前 8 个寄存器参数,
 * 无法恢复的为 0):
 *   普通函数      a0=第一个参数,a1=第二个参数,...
 *   C++ 实例方法 a0=this,a1=第一个显式参数,...
 * 返回 0 跳过目标代码,非 0 放行。 */
int instr_guard_block(void *fn, void *block_start, void *block_end,
                      void *check);

/* 卸载:恢复原指令、释放 trampoline。传 block_start。 */
int instr_unpatch(void *patched_addr);

/* 最近一次错误的描述字符串 */
const char *instr_last_error(void);
```

错误码见 `include/instr.h` 中的 `enum`。

## 构建

### Android (NDK)

```sh
# Windows
powershell -ExecutionPolicy Bypass -File tools/build.ps1
# Linux/macOS
export ANDROID_NDK_HOME=/path/to/ndk
./tools/build_android.sh
```

或使用 CMake:

```sh
cmake -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 .
cmake --build .
```

产物:`build/libinstr.so`(引擎库)、`build/libtarget_block.so` / `build/libtarget_cpp.so`
(演示目标)、`build/demo_main`(演示程序)。

### 演示

```sh
adb push build/demo_main build/libtarget_block.so build/libtarget_cpp.so /data/local/tmp/
adb shell "cd /data/local/tmp && LD_LIBRARY_PATH=. ./demo_main block"  # main 代码块
adb shell "cd /data/local/tmp && LD_LIBRARY_PATH=. ./demo_main cpp"    # 实例方法
```

### 宿主机测试(无需 ARM64 设备)

依赖:Python 3 + `tools/pylibs` 下的 capstone / unicorn
(首次运行 `py tools/fetch_pylibs.py`),zig 编译宿主机测试程序(`tools/fetch_zig.py`)。

```sh
powershell -ExecutionPolicy Bypass -File tools/build.ps1   # 构建 + 逻辑测试
py tools/verify.py          # capstone 交叉校验 + unicorn 端到端
py tools/verify_cpp.py      # 实例方法端到端
py tools/verify_realcheck.py # 真实 check 函数(声明少参数)端到端
```

验证覆盖:指令编码/解码/重定位与 capstone 交叉核对、NDK r28 产物
(文件偏移 ≠ 虚拟地址、PLT 头 32 字节)的符号/PLT/GOT 解析、-O0/-O2 参数分析、
92 万字节大函数、C++ 实例方法、真实 ABI 调用。

## 目录结构

```
include/instr.h           公共 API(唯一头文件)
src/a64.c                  AArch64 指令 编码/解码/重定位
src/elf64.c                内存中解析 ELF64 模块(符号/PLT/GOT/段换算)
src/analysis.c             入口参数(x0~x7)存活位置数据流分析
src/instr_plan.c           trampoline 发射、补丁字节、搬移指令重映射
src/instr.c                运行时应用:dladdr、mmap、mprotect、cache flush、卸载
demo/                      演示目标与程序(普通函数 / 代码块 / C++ 实例方法)
tests/                     宿主机逻辑测试
tools/                     构建与验证脚本(NDK / zig / capstone / unicorn)
```

## 限制

- 目标平台:AArch64 小端 ELF(Android / Linux)。
- `block_end - block_start >= 12/16 字节`(补丁空间);块内指向补丁区内部的分支
  已被重映射处理,但指向补丁字节中间的非对齐跳转不受支持(正常编译器不会产生)。
- 插桩须在目标函数被执行之前完成;不要在目标代码热路径上并发插桩。
- Android 受限应用对代码页 `mprotect(RWX)` 可能被 SELinux 拒绝,
  建议在 root / 调试构建 / `adb shell` 下运行(所有 inline 类技术的共同限制)。
- 数据流分析对无法解码的指令按"写 Rd"保守处理;若守卫点前出现大量非常规指令
  导致无法定位参数,返回 `INSTR_ERR_NOLOC`。
- check 与目标代码不要相互递归调用被守卫的函数。

## License

[MIT](LICENSE)
