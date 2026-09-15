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
- **入口快照模式(dobby 级万能)**:`instr_guard_block_snap` 在函数入口打 16 字节
  快照补丁,把入口 x0~x7 原样保存;守卫点 check **100%** 收到入口参数,
  与函数内部把参数搬到哪里、指令多复杂、数据流是否可分析完全无关
- **复杂函数参数恢复**:支持 8 参数、pre/post-index 压栈与槽位重定基、
  任意基址槽(sp / x29 / x19~x28 等)、字节/半字存取、>4KB 大栈帧偏移;
  must 语义保证**绝不把错误位置传给 check**(无法恢复的按 0 传)
- **实例方法支持**:C++ 成员函数入口参数 `a0=this, a1=第一个显式参数, ...`,
  与 hook 框架的替换函数约定一致
- **大函数支持**:目标函数上限 1M 条指令(约 4MB 代码),实测 92 万字节函数正常插桩
- **完全位置无关的 trampoline**:所有绝对地址经内联字面量池,无距离限制
- **可卸载**:恢复原指令并释放 trampoline
- **安全**:补丁前分析失败、范围非法、重定位不支持等均返回错误码而非越界;
  分析为 must 语义,错误时宁可 NOLOC / 传 0 也不传错值

## 工作原理

1. **参数存活位置分析**(无需调试信息):从函数入口做前向必经数据流分析,
   确定入口参数 x0~x7 中每一个在守卫点处的存活位置(寄存器或栈槽
   `[base, #off]`,base 可以是 sp / x29 / 任意未被改写的非易失基寄存器)。
   处理 `mov` 拷贝、`str/stp` 压栈(含 pre/post-index 写回的槽位重定基)、
   `add x29, sp` 帧基换算、`bl` 清除 caller-saved、字节/半字存取、
   任意偏移(>4096 的大栈帧)等。分析是 **must 语义**:只在所有路径上都
   成立的位置才会被报告 —— **要么给出真实可信的位置,要么报不可恢复(传 0),
   绝不把错误地址/寄存器传给 check**。
2. **补丁**:在守卫点改写 12 或 16 字节跳转到 trampoline
   (形态 A:`adrp/add/br`,距守卫 <4GB;形态 B:`ldr/br/.quad`,无距离限制)。
   被覆盖的原指令搬移进 trampoline 重放;若其中含有指向补丁区的分支
   (如循环跳回),目标会被重映射到该指令在 trampoline 里的新地址。
3. **trampoline**:保存**全部** GPR(x0~x30)+ NZCV + 开辟参数暂存区
   → 恢复入口参数到 x0~x7 → 调用 check → 通过则**恢复完整现场**后重放
   被搬移指令并继续;拒绝则恢复现场后直接跳到代码块末尾。
   全寄存器保存/恢复保证:check 与参数恢复阶段可以任意使用暂存寄存器,
   被搬移指令重放时读到的寄存器与守卫点完全一致(不再有暂存污染)。

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

公共 API 共 4 个:

```c
/* 主 API(数据流模式):守卫 fn 内 [block_start, block_end) 的代码块。
 * check 为任意签名的函数指针(传 (void*)check 即可)。调用时按 AArch64
 * 调用约定把目标函数"入口"的 x0~x7 传给它(前 8 个寄存器参数,
 * 无法恢复的为 0):
 *   普通函数      a0=第一个参数,a1=第二个参数,...
 *   C++ 实例方法 a0=this,a1=第一个显式参数,...
 * 返回 0 跳过目标代码,非 0 放行。 */
int instr_guard_block(void *fn, void *block_start, void *block_end,
                      void *check);

/* 入口快照模式(dobby 级万能):参数不靠数据流分析,而是在 fn 入口打 16 字节
 * 快照补丁把 x0~x7 原样保存,守卫点 100% 收到入口参数。
 * 要求 block_start >= fn + 16;同一函数只支持安装一个快照守卫;
 * 代价:入口被改写(指令级等价)+ 每次调用多一次保存/恢复。 */
int instr_guard_block_snap(void *fn, void *block_start, void *block_end,
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
92 万字节大函数、C++ 实例方法、真实 ABI 调用、**复杂函数 8 参数端到端
(5KB 大栈帧 + 全部参数压栈恢复,unicorn 断言 check 收到与入口完全一致的 a0~a7)**、
解码语料与 NDK clang 逐条对照、pre/post-index/字节存取/基址改写等数据流单元测试。

## 目录结构

```
include/instr.h           公共 API(唯一头文件)
src/a64.c                  AArch64 指令 编码/解码/重定位
src/elf64.c                内存中解析 ELF64 模块(符号/PLT/GOT/段换算)
src/analysis.c             入口参数(x0~x7)存活位置数据流分析
src/instr_plan.c           trampoline 发射、补丁字节、搬移指令重映射
src/instr.c                运行时应用:dladdr、mmap、mprotect、cache flush、卸载
demo/                      演示目标与程序(普通函数 / 代码块 / C++ 实例方法 / 复杂函数)
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
- 数据流分析为 must 语义:**只在所有路径上都成立的位置才会被报告**;
  若守卫点前参数已被彻底改写、或经过分析器无法静态跟踪的指令
  (寄存器间接跳转、不可解码指令、以 x8~x17 为基址的槽位等),
  该参数按 0 传给 check —— **不会把错误位置传给 check**。
  守卫点前若出现大量无法定位的参数,返回 `INSTR_ERR_NOLOC`(不产生补丁)。
  需要"参数一定拿得到"时用入口快照模式(`instr_guard_block_snap`)。
- 入口快照模式限制:会改写 fn 入口 16 字节(指令级等价);每次调用该函数
  多一次保存/恢复的开销;守卫点到达前若同一函数被递归/自调用重新进入,
  快照会被内层覆盖(罕见)。
- **同一函数可装多个块守卫共享一个入口快照**:第一次 `instr_guard_block_snap`
  建立入口快照 + 该块;后续对同一函数的 `instr_guard_block_snap` 自动复用
  既有快照区,只追加块守卫 —— 多个块(如 Player.Update 的物理块+液体块)
  都能从入口快照拿到 x0~x7,check 不依赖任何数据流分析。
- check 与目标代码不要相互递归调用被守卫的函数。
- **check 是普通 C 函数,可破坏调用者保存的浮点寄存器(d0~d7、d16~d31)**:
  trampoline 已保存/恢复 d0~d31 —— 守卫的代码块常是浮点重负载(物理/碰撞/
  液体计算),不恢复 FP 会导致块内计算错乱(NaN)→ 死循环/崩溃。skip 路径
  不执行块内代码看不出问题,pass 路径(正常执行块)必现。
- 分析窗口上限 256K 条指令:守卫点距函数入口超过该距离时报 `INSTR_ERR_NOLOC`
  (快照模式不受此限)。

## 与 Dobby 等 hook 框架共存

两者都靠改写代码字节,遵守以下规则可避免冲突:

| 场景 | 是否可共存 | 说明 |
|---|---|---|
| 不同函数:一个用 arm64-guard,另一个用 Dobby | ✅ | 互不影响 |
| 同一函数:Dobby(hook 入口)+ `instr_guard_block`(数据流,不碰入口) | ✅ | **必须 arm64-guard 先装、Dobby 后装**(或保证入口未被改写时安装):块守卫读**运行时内存**分析参数,入口若已被 Dobby 改写为跳转会 NOLOC(与 9ed5149 之前的语义一致)。之所以不用磁盘镜像分析——磁盘 .so 可能与进程内实际映射不一致(游戏自修改/多 mod 共存),按镜像生成的搬移指令/参数位置会出错 → 守卫通过路径执行损坏(实测 Player.Update 双守卫后进世界卡死)。快照模式仍读镜像(入口链式共存需要) |
| 同一函数:Dobby + `instr_guard_block_snap` | ✅(需先装 Dobby) | **hook 链共存**:先装 Dobby,再装快照守卫 —— 快照安装前检测到入口已被占用,自动解析现有 hook(形态 A `adrp/add/br`、形态 B `ldr/br/.quad`,寄存器 x16/x17 均可;Dobby 的 TMP_REG_0 = x17)并链式接入:入口先走我们的快照 trampoline 保存 x0~x7,再跳进 Dobby 的 trampoline 正常执行 —— 两条 hook 同时生效,互不覆盖。**注意**:Dobby 的重定位代码(T_D)会跳回 `fn + Dobby补丁长度` 继续(形态 A=12B 跳回 fn+12),因此链式入口补丁**不得超过** Dobby 补丁长度(形态 A 用 12B `adrp/add/br`,形态 C 用 4B `b`),否则覆盖 T_D 跳回目标 → 执行补丁数据崩溃 |
| 同一函数:先装 `instr_guard_block_snap` 再装 Dobby | ⚠️ 不保证 | Dobby 会把我们的入口补丁当作"原始指令"搬进它的 trampoline,行为取决于 Dobby 实现;同一函数建议按"Dobby 先、快照后"的顺序 |
| 入口被无法识别的 hook 占用(非 ldr/br 或 adrp/add/br 形态,且非单条 `b`) | ❌ | 返回 `INSTR_ERR_ENTRY_BUSY`,拒绝静默覆盖 |

要点:同一函数上**入口只能有一个主人** —— 想 hook 入口用 Dobby(或
`instr_guard_block_snap`,可链在 Dobby 之后),想在函数内部做条件执行守卫用
`instr_guard_block`,三者可按上表组合。

## License

[MIT](LICENSE)
