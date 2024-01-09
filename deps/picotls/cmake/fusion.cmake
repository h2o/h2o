INCLUDE(CheckCSourceCompiles)
INCLUDE(CMakePushCheckState)

FUNCTION (CHECK_FUSION_PREREQUISITES)
    MESSAGE(STATUS "Detecting fusion support")

    CMAKE_PUSH_CHECK_STATE()
    SET(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -mavx2 -maes -mpclmul -mvaes -mvpclmulqdq")
    CHECK_C_SOURCE_COMPILES("
    #include <emmintrin.h>
    #include <immintrin.h>
    int main(void) {
        __m256i  ord0, ord1, ord2, ord3 = _mm256_setzero_si256();
        ord0 = _mm256_aesenc_epi128(ord1, ord2);
        ord3 = _mm256_aesenclast_epi128(ord0, ord1);
        ord1 = _mm256_clmulepi64_epi128(ord3, ord2, 0x00);
        _mm_insert_epi64(_mm_setr_epi32(0, 1, 2, 3), 0, 0);
        return 0;
    }
    " CC_HAS_AESNI256)
    CMAKE_POP_CHECK_STATE()

    IF (CC_HAS_AESNI256)
        MESSAGE(STATUS "Can use fusion")
        SET(WITH_FUSION_DEFAULT "ON" PARENT_SCOPE)
    ELSE ()
        MESSAGE(STATUS "Cannot use fusion")
        SET(WITH_FUSION_DEFAULT "OFF" PARENT_SCOPE)
    ENDIF ()
ENDFUNCTION ()
