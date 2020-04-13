cmake_minimum_required(VERSION 3.10)

project(simplecrypto-cxx)

add_subdirectory(simplecrypto-cxx)
add_subdirectory(benchmark)

include_directories(simplecrypto-cxx)

add_executable(main
    main.cpp)
add_executable(bench bench.cpp)
add_executable(bench_c bench_c.cpp sha2.cpp)

target_link_libraries(main PRIVATE simplecrypto-cxx)
target_link_libraries(bench PRIVATE benchmark::benchmark simplecrypto-cxx)
target_link_libraries(bench_c PRIVATE benchmark::benchmark  simplecrypto-cxx)
