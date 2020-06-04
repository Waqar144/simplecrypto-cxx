add_library(simplecrypto-cxx
                    base58.cpp
                    sha224.cpp
                    sha256.cpp
                    sha384.cpp
                    sha512.cpp
                    ripemd160.cpp
                    hmac.cpp
                    pbkdf2.cpp
                    sha3.cpp
                    blake3.cpp)

set_target_properties(simplecrypto-cxx PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

add_library(project_options INTERFACE)

if(${CMAKE_VERSION} VERSION_LESS "3.12.4")
        message("Please consider to switch to CMake >= 3.12.4 to enable sanitizers")
else()
    include(cmake/sanitizers.cmake)
    enable_sanitizers(project_options)
endif()

target_link_libraries(simplecrypto-cxx INTERFACE project_options)


add_library(project_warnings INTERFACE)

# standard compiler warnings
include(cmake/warnings.cmake)
set_project_warnings(project_warnings)

#BLAKE-3 Library
add_subdirectory(blake3)
target_link_libraries(simplecrypto-cxx PRIVATE blake3lib)

target_link_libraries(simplecrypto-cxx INTERFACE project_warnings)
target_link_libraries(simplecrypto-cxx INTERFACE project_options )
