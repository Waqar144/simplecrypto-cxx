cmake_minimum_required(VERSION 3.13)

project(simplecrypto-cxx)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (MSVC)
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
endif()

set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "Suppressing benchmark's tests" FORCE)
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Suppressing benchmark's tests" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "Not building GMock")
set(INSTALL_GTEST OFF CACHE BOOL "INSTALL_GTEST OFF")
set(BENCHMARK_ENABLE_INSTALL "BENCHMARK INSTALL OFF" OFF)
set(BENCHMARK_ENABLE_EXCEPTIONS OFF)

option(SIMPLECRYPTO_ENABLE_BENCH "Enable benchmarks" OFF)
option(SIMPLECRYPTO_ENABLE_TESTS "Enable testing" OFF)

add_subdirectory(simplecrypto-cxx)

if(SIMPLECRYPTO_ENABLE_BENCH)
add_subdirectory(3rdparty/benchmark)
endif()

if(SIMPLECRYPTO_ENABLE_TESTS)
add_subdirectory(3rdparty/googletest)
include_directories(3rdparty/googletest/googletest/include)
add_subdirectory(tests)
endif()

include_directories(simplecrypto-cxx)


if(SIMPLECRYPTO_ENABLE_BENCH)
add_executable(bench bench.cpp)

target_link_libraries(bench PRIVATE benchmark::benchmark simplecrypto-cxx)
endif()


