cmake_minimum_required(VERSION 3.10)

project(simplecrypto-cxx)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(BENCHMARK_ENABLE_GTEST_TESTS OFF)
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Suppressing benchmark's tests" FORCE)

add_subdirectory(simplecrypto-cxx)
add_subdirectory(3rdparty/benchmark)
add_subdirectory(3rdparty/googletest)
add_subdirectory(tests)

include_directories(simplecrypto-cxx)
include_directories(3rdparty/googletest/googletest/include)

add_executable(main
    main.cpp)
add_executable(bench bench.cpp)
add_executable(bench_c bench_c.cpp sha2.cpp)

target_link_libraries(main PRIVATE simplecrypto-cxx)
target_link_libraries(bench PRIVATE benchmark::benchmark simplecrypto-cxx)
target_link_libraries(bench_c PRIVATE benchmark::benchmark simplecrypto-cxx)
