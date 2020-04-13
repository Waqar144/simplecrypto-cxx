add_executable(testmain testmain.cpp)

include_directories(../simplecrypto-cxx/)

target_link_libraries(testmain PRIVATE gtest simplecrypto-cxx)
