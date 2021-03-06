include(CheckCSourceRuns.cmake)
option(ENABLE_SSE "Enable compile-time SSE4.1 support." ON)
option(ENABLE_AVX "Enable compile-time AVX support."  ON)
option(ENABLE_AVX2 "Enable compile-time AVX2 support."  ON)

if (ENABLE_SSE)
    #
    # Check compiler for SSE4_1 intrinsics
    #
    if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_CLANG )
        set(CMAKE_REQUIRED_FLAGS "-msse4.1")
        check_c_source_runs("
        #include <emmintrin.h>
        #include <smmintrin.h>

        int main()
        {
        __m128i a = _mm_setzero_si128();
        __m128i b = _mm_minpos_epu16(a);
        return 0;
        }"
        HAVE_SSE)
    endif()

    if (HAVE_SSE)
        message(STATUS "SSE4.1 is enabled - target CPU must support it")
    endif()

    if (ENABLE_AVX512)

        #
        # Check compiler for AVX intrinsics
        #
        if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_CLANG )
            set(CMAKE_REQUIRED_FLAGS "-mavx")
            check_c_source_runs("
            #include <immintrin.h>
            int main()
            {
              __m256 a, b, c;
              const float src[8] = { 1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f };
              float dst[8];
              a = _mm256_loadu_ps( src );
              b = _mm256_loadu_ps( src );
              c = _mm256_add_ps( a, b );
              _mm256_storeu_ps( dst, c );
              int i = 0;
              for( i = 0; i < 8; i++ ){
                if( ( src[i] + src[i] ) != dst[i] ){
                  return -1;
                }
              }
              return 0;
            }"
            HAVE_AVX)
        endif()

        if (HAVE_AVX)
            message(STATUS "AVX is enabled - target CPU must support it")
        endif()
    endif()

    if (ENABLE_AVX2)

      #
      # Check compiler for AVX intrinsics
      #
      if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_CLANG )
          set(CMAKE_REQUIRED_FLAGS "-mavx2")
          check_c_source_runs("
          #include <immintrin.h>
          int main()
          {
            __m256i a, b, c;
            const int src[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
            int dst[8];
            a =  _mm256_loadu_si256( (__m256i*)src );
            b =  _mm256_loadu_si256( (__m256i*)src );
            c = _mm256_add_epi32( a, b );
            _mm256_storeu_si256( (__m256i*)dst, c );
            int i = 0;
            for( i = 0; i < 8; i++ ){
              if( ( src[i] + src[i] ) != dst[i] ){
                return -1;
              }
            }
            return 0;
          }"
          HAVE_AVX2)
      endif()

      if (HAVE_AVX2)
          message(STATUS "AVX2 is enabled - target CPU must support it")
      endif()
  endif()

endif()

mark_as_advanced(HAVE_SSE, HAVE_AVX, HAVE_AVX2)

#disable AVX512 for now
set(BLAKE3_COMPILE_DEFS BLAKE3_NO_AVX512)

set(BLAKE3_LIB_SOURCES BLAKE3/c/blake3.c BLAKE3/c/blake3_dispatch.c BLAKE3/c/blake3_portable.c)
set(BLAKE3_COMPILE_OPTIONS "")

if (HAVE_SSE)
    list(APPEND BLAKE3_LIB_SOURCES BLAKE3/c/blake3_sse41.c)
    if (MSVC)
        list(APPEND BLAKE3_COMPILE_OPTIONS /arch:SSE2)
    else()
        list(APPEND BLAKE3_COMPILE_OPTIONS -msse4.1)
    endif()
else()
    list(APPEND BLAKE3_COMPILE_DEFS BLAKE3_NO_SSE41)
endif()
if (HAVE_AVX2)
    list(APPEND BLAKE3_LIB_SOURCES BLAKE3/c/blake3_avx2.c)
    if (MSVC)
        list(APPEND BLAKE3_COMPILE_OPTIONS /arch:AVX2)
    else()
        list(APPEND BLAKE3_COMPILE_OPTIONS -mavx2)
    endif()
else()
    list(APPEND BLAKE3_COMPILE_DEFS BLAKE3_NO_AVX2)
endif()

add_library(blake3lib STATIC ${BLAKE3_LIB_SOURCES})

if (MSVC)
set(MSVC_COMPILE_DEBUG_OPTIONS "${BLAKE3_COMPILE_OPTIONS} /MTd")
set(MSVC_COMPILE_RELEASE_OPTIONS "${BLAKE3_COMPILE_OPTIONS} /MT")
target_compile_options(blake3lib PUBLIC "$<$<CONFIG:Debug>:${MSVC_COMPILE_DEBUG_OPTIONS}>")
target_compile_options(blake3lib PUBLIC "$<$<CONFIG:Release>:${MSVC_COMPILE_RELEASE_OPTIONS}>")
else()
target_compile_options(blake3lib PRIVATE ${BLAKE3_COMPILE_OPTIONS})
endif()

target_compile_definitions(blake3lib PUBLIC ${BLAKE3_COMPILE_DEFS})

