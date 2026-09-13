cmake_minimum_required(VERSION 3.10)
project(instr C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)

set(INSTR_SRCS
    src/a64.c
    src/elf64.c
    src/analysis.c
    src/instr_plan.c
    src/instr.c
)

# 插桩引擎库(libinstr.so)
add_library(instr SHARED ${INSTR_SRCS})
target_include_directories(instr PUBLIC include PRIVATE src)
set_target_properties(instr PROPERTIES OUTPUT_NAME "instr")

# 演示目标
add_library(target_block SHARED demo/libtarget_block.c)
set_target_properties(target_block PROPERTIES OUTPUT_NAME "libtarget_block")

add_library(target_cpp SHARED demo/libtarget_cpp.cpp)
set_target_properties(target_cpp PROPERTIES OUTPUT_NAME "libtarget_cpp")

# 演示程序
add_executable(demo_main demo/demo_main.c demo/mycheck.c ${INSTR_SRCS})
target_include_directories(demo_main PRIVATE include src)
target_link_libraries(demo_main dl log)

# 宿主机逻辑测试(仅逻辑部分,不含 instr.c 的系统调用)
add_executable(test_logic tests/test_logic.c src/a64.c src/elf64.c
               src/analysis.c src/instr_plan.c)
target_include_directories(test_logic PRIVATE include src)
