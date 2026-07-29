cmake_minimum_required(VERSION 3.22.1)
project("native_core")

add_library(native_core SHARED native_core.c)

target_include_directories(native_core PRIVATE ${ANDROID_NDK})

target_compile_options(native_core PRIVATE 
    -O2 
    -fvisibility=hidden 
    -fstack-protector-strong 
    -Wall -Werror
)

target_link_options(native_core PRIVATE 
    -Wl,-z,relro 
    -Wl,-z,noexecstack 
    -Wl,--gc-sections
)
