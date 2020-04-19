add_library(simplecrypto-cxx base58.cpp sha256.cpp sha512.cpp ripemd160.cpp)

add_library(project_options INTERFACE)
target_compile_features(project_options INTERFACE cxx_std_17)

include(cmake/sanitizers.cmake)
enable_sanitizers(project_options)

add_library(project_warnings INTERFACE)

# standard compiler warnings
include(cmake/warnings.cmake)
set_project_warnings(project_warnings)

target_link_libraries(simplecrypto-cxx INTERFACE project_warnings)
target_link_libraries(simplecrypto-cxx INTERFACE project_options )
