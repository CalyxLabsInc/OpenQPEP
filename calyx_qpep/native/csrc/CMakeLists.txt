# OpenQPEP Official Release 1.2.7 (v1.2.7) — Cross-Platform C99 / SIMD SDK CMakeLists.txt
# Builds both shared (libopenqpep.so/.dylib/.dll) and static (libopenqpep.a) libraries,
# Android NDK JNI target, public header include/openqpep.h, and pkg-config openqpep.pc.
cmake_minimum_required(VERSION 3.16)
project(openqpep VERSION 1.2.7 LANGUAGES C)

include(GNUInstallDirs)

option(OPENQPEP_BUILD_SHARED "Build shared libopenqpep library" ON)
option(OPENQPEP_BUILD_STATIC "Build static libopenqpep library" ON)
option(OPENQPEP_PORTABLE "Disable host-specific AVX2/NEON SIMD flags for portable builds" OFF)
option(OPENQPEP_BUILD_JNI "Include Android NDK JNI bridge in shared target" OFF)

set(OPENQPEP_CORE_SRCS
    ntt_3329.c
    ntt_8380417.c
    cbd.c
    pentad_accel.c
    keccak_f1600.c
    poly_ring_c.c
    plain_lwe_c.c
    goppa_c.c
    rank_uov_c.c
    wire_c.c
    qhs_c.c
)

set(OPENQPEP_SHARED_SRCS ${OPENQPEP_CORE_SRCS})
if(ANDROID OR OPENQPEP_BUILD_JNI)
    list(APPEND OPENQPEP_SHARED_SRCS openqpep_jni.c)
endif()

function(openqpep_configure_target tgt)
    set_target_properties(${tgt} PROPERTIES
        C_STANDARD 99
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
        C_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
        POSITION_INDEPENDENT_CODE ON
    )
    target_include_directories(${tgt}
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )
    if(MSVC)
        target_compile_options(${tgt} PRIVATE /O2 /W4 /WX)
    else()
        target_compile_options(${tgt} PRIVATE
            -O3
            -Wall
            -Wextra
            -Werror
            -Wpedantic
            -Wstrict-prototypes
            -Wmissing-prototypes
        )
        if(NOT OPENQPEP_PORTABLE)
            if(ANDROID AND ANDROID_ABI STREQUAL "arm64-v8a")
                target_compile_options(${tgt} PRIVATE -march=armv8-a+simd -ftree-vectorize)
            elseif(ANDROID AND ANDROID_ABI STREQUAL "x86_64")
                target_compile_options(${tgt} PRIVATE -mavx2 -ftree-vectorize)
            elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$")
                target_compile_options(${tgt} PRIVATE -mavx2 -ftree-vectorize)
            elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
                target_compile_options(${tgt} PRIVATE -march=armv8-a -ftree-vectorize)
            endif()
        endif()
    endif()
endfunction()

if(OPENQPEP_BUILD_SHARED)
    add_library(openqpep SHARED ${OPENQPEP_SHARED_SRCS})
    openqpep_configure_target(openqpep)
    target_compile_definitions(openqpep PRIVATE OPENQPEP_BUILDING_DLL)
    set_target_properties(openqpep PROPERTIES
        OUTPUT_NAME openqpep
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
    install(TARGETS openqpep
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

if(OPENQPEP_BUILD_STATIC)
    add_library(openqpep_static STATIC ${OPENQPEP_CORE_SRCS})
    openqpep_configure_target(openqpep_static)
    target_compile_definitions(openqpep_static PUBLIC OPENQPEP_STATIC)
    set_target_properties(openqpep_static PROPERTIES
        OUTPUT_NAME openqpep
    )
    install(TARGETS openqpep_static
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()

# Generate pkg-config manifest (openqpep.pc)
set(PREFIX "${CMAKE_INSTALL_PREFIX}")
set(LIBDIR "\${prefix}/${CMAKE_INSTALL_LIBDIR}")
set(INCLUDEDIR "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
set(VERSION "${PROJECT_VERSION}")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/openqpep.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/openqpep.pc"
    @ONLY
)

install(FILES include/openqpep.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/openqpep.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
