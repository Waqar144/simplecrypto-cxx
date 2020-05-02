cmake_minimum_required(VERSION 3.12)

project(simplecrypto-cxx)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (MSVC)
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
endif()

set(BENCHMARK_ENABLE_GTEST_TESTS OFF)
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Suppressing benchmark's tests" FORCE)

OPTION(SIMPLECRYPTO_ENABLE_BENCH "Enable benchmarks" OFF)
OPTION(SIMPLECRYPTO_ENABLE_TESTS "Enable testing" OFF)

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

add_executable(main
    main.cpp)

if(SIMPLECRYPTO_ENABLE_BENCH)
add_executable(bench bench.cpp)

target_link_libraries(bench PRIVATE benchmark::benchmark simplecrypto-cxx)
endif()

target_link_libraries(main PRIVATE simplecrypto-cxx)
target_link_libraries(main PRIVATE blake3lib)

