add_executable(testmain testmain.cpp sha3_tests.h test_utils.h blake3_tests.h)

include_directories(../simplecrypto-cxx/)

target_link_libraries(testmain PRIVATE gtest simplecrypto-cxx)
