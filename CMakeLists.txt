cmake_minimum_required(VERSION 3.10)

project(simplecrypto-cxx)

add_subdirectory(simplecrypto-cxx)

add_executable(main
    main.cpp)

target_link_libraries(main PRIVATE simplecrypto-cxx)
