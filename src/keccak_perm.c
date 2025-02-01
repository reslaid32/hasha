/*
 * keccak_perm.c
 *
 * This file defines three variants of the Keccak‑f[1600] permutation:
 *
 *   1. A software (plain C) implementation, available via keccak_permutation_software().
 *   2. A SIMD version using AVX2 (operates on 4 states in parallel).
 *   3. A “nano” version using ARM NEON (operates on 2 states in parallel).
 *
 * The wrapper function, keccak_permutation(), always accepts a pointer to
 * 25 uint64_t words (a single Keccak state) and will call the accelerated variant
 * if available, or fall back to the software version.
 *
 * In addition, the new function keccak_permutation_batch() processes an array of
 * states concurrently using OpenMP to utilize all available CPU threads.
 *
 * The variant is selected entirely at compile time. No runtime dispatch is used.
 */

#include "../include/hasha/keccak_perm.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

// #ifdef _OPENMP
// #include <omp.h>
// #endif

/*-----------------------------------------------------------------------------
  Configuration: choose acceleration at compile time

  - If KECCAK_DISABLE_ACCELERATION is defined then neither SIMD nor nano is used.
  - Otherwise, if __AVX2__ is defined then the SIMD (AVX2) version is used.
  - Otherwise, if KECCAK_USE_NANO is defined then the nano (NEON) version is used.
  - Otherwise, fall back to the software version.
-----------------------------------------------------------------------------*/
#if defined(KECCAK_DISABLE_ACCELERATION)
  #define KECCAK_ACCELERATION 0
#elif defined(__AVX2__)
  #define KECCAK_ACCELERATION 1
#elif defined(KECCAK_USE_NANO)
  #define KECCAK_ACCELERATION 2
#else
  #define KECCAK_ACCELERATION 0
#endif

/* --- Shared Constants --- */
#define SHA3_KECCAK_ROUNDS 24
static const uint64_t SHA3_KECCAK_ROUND_CONSTANTS[SHA3_KECCAK_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int SHA3_RHO_OFFSETS[5][5] = {
    {  0,  36,   3,  41,  18 },
    {  1,  44,  10,  45,   2 },
    { 62,   6,  43,  15,  61 },
    { 28,  55,  25,  21,  56 },
    { 27,  20,  39,   8,  14 }
};

/*=============================================================================
   Variant 0: Software Implementation (Plain C)
   The state is an array of 25 uint64_t words.
   This function is now named keccak_permutation_software().
   Additional optimizations:
     - Loop unrolling in theta, rho_pi, and chi.
     - Compute independent values in parallel.
  ===========================================================================*/
#if KECCAK_ACCELERATION == 0 || defined(KECCAK_DISABLE_ACCELERATION)

HASHA_PRIVATE_FUNC void theta_software(uint64_t *state) {
    uint64_t C0, C1, C2, C3, C4;
    uint64_t D0, D1, D2, D3, D4;

    // Manually unroll the column parity calculations
    C0 = state[0]  ^ state[5]  ^ state[10] ^ state[15] ^ state[20];
    C1 = state[1]  ^ state[6]  ^ state[11] ^ state[16] ^ state[21];
    C2 = state[2]  ^ state[7]  ^ state[12] ^ state[17] ^ state[22];
    C3 = state[3]  ^ state[8]  ^ state[13] ^ state[18] ^ state[23];
    C4 = state[4]  ^ state[9]  ^ state[14] ^ state[19] ^ state[24];

    // Compute D values; rotations are done inline.
    D0 = C4 ^ ((C1 << 1) | (C1 >> (64 - 1)));
    D1 = C0 ^ ((C2 << 1) | (C2 >> (64 - 1)));
    D2 = C1 ^ ((C3 << 1) | (C3 >> (64 - 1)));
    D3 = C2 ^ ((C4 << 1) | (C4 >> (64 - 1)));
    D4 = C3 ^ ((C0 << 1) | (C0 >> (64 - 1)));

    // Unrolled state update; each column is updated separately.
    state[ 0] ^= D0;  state[ 5] ^= D0;  state[10] ^= D0;  state[15] ^= D0;  state[20] ^= D0;
    state[ 1] ^= D1;  state[ 6] ^= D1;  state[11] ^= D1;  state[16] ^= D1;  state[21] ^= D1;
    state[ 2] ^= D2;  state[ 7] ^= D2;  state[12] ^= D2;  state[17] ^= D2;  state[22] ^= D2;
    state[ 3] ^= D3;  state[ 8] ^= D3;  state[13] ^= D3;  state[18] ^= D3;  state[23] ^= D3;
    state[ 4] ^= D4;  state[ 9] ^= D4;  state[14] ^= D4;  state[19] ^= D4;  state[24] ^= D4;
}

HASHA_PRIVATE_FUNC void rho_pi_software(uint64_t *state) {
    uint64_t tmp[25];
    int x, y;
    // Copy state to temporary array for unrolling
    for (x = 0; x < 25; ++x) {
        tmp[x] = state[x];
    }
    // Unrolled nested loops: for each (x,y), compute new position with rotation.
    for (y = 0; y < 5; ++y) {
        for (x = 0; x < 5; ++x) {
            int offset = SHA3_RHO_OFFSETS[x][y];
            int newX = y;
            int newY = (2 * x + 3 * y) % 5;
            int newIndex = newX + 5 * newY;
            state[newIndex] = (tmp[x + 5*y] << offset) | (tmp[x + 5*y] >> (64 - offset));
        }
    }
}

HASHA_PRIVATE_FUNC void chi_software(uint64_t *state) {
    uint64_t tmp[25];
    int x, y;
    // Copy state into temporary array
    for (x = 0; x < 25; ++x)
        tmp[x] = state[x];
    // Process rows in an unrolled manner
    for (y = 0; y < 5; ++y) {
        state[0 + 5*y] = tmp[0 + 5*y] ^ ((~tmp[1 + 5*y]) & tmp[2 + 5*y]);
        state[1 + 5*y] = tmp[1 + 5*y] ^ ((~tmp[2 + 5*y]) & tmp[3 + 5*y]);
        state[2 + 5*y] = tmp[2 + 5*y] ^ ((~tmp[3 + 5*y]) & tmp[4 + 5*y]);
        state[3 + 5*y] = tmp[3 + 5*y] ^ ((~tmp[4 + 5*y]) & tmp[0 + 5*y]);
        state[4 + 5*y] = tmp[4 + 5*y] ^ ((~tmp[0 + 5*y]) & tmp[1 + 5*y]);
    }
}

HASHA_PRIVATE_FUNC void iota_software(uint64_t *state, int round) {
    state[0] ^= SHA3_KECCAK_ROUND_CONSTANTS[round];
}

HASHA_PUBLIC_FUNC void keccak_permutation_software(uint64_t *state) {
    int round;
    for (round = 0; round < SHA3_KECCAK_ROUNDS; ++round) {
        theta_software(state);
        rho_pi_software(state);
        chi_software(state);
        iota_software(state, round);
    }
}

#endif  /* End of software implementation */


/*=============================================================================
   Variant 1: SIMD Implementation (AVX2)
   Each state is represented as an array of 25 __m256i values (4 lanes per vector).
   Additional unrolling is applied in inner loops.
  ===========================================================================*/
#if KECCAK_ACCELERATION == 1

#include <immintrin.h>

static inline __m256i ROTL64(__m256i x, int n) {
    return _mm256_or_si256(_mm256_slli_epi64(x, n),
                           _mm256_srli_epi64(x, 64 - n));
}

HASHA_PRIVATE_FUNC void theta_simd(__m256i state[25]) {
    __m256i C[5], D[5];
    int x, i;
    // Unroll the computation of C[x]
    for (x = 0; x < 5; ++x) {
        C[x] = _mm256_xor_si256(state[x],
              _mm256_xor_si256(state[x+5],
              _mm256_xor_si256(state[x+10],
              _mm256_xor_si256(state[x+15], state[x+20]))));
    }
    for (x = 0; x < 5; ++x) {
        __m256i t = ROTL64(C[(x+1)%5], 1);
        D[x] = _mm256_xor_si256(C[(x+4)%5], t);
    }
    for (i = 0; i < 25; ++i) {
        state[i] = _mm256_xor_si256(state[i], D[i % 5]);
    }
}

HASHA_PRIVATE_FUNC void rho_pi_simd(__m256i state[25]) {
    __m256i B[25];
    int x, y;
    for (y = 0; y < 5; ++y) {
        for (x = 0; x < 5; ++x) {
            int index = x + 5*y;
            int newX = y;
            int newY = (2*x + 3*y) % 5;
            int newIndex = newX + 5*newY;
            int offset = SHA3_RHO_OFFSETS[x][y];
            B[newIndex] = ROTL64(state[index], offset);
        }
    }
    for (x = 0; x < 25; ++x) {
        state[x] = B[x];
    }
}

HASHA_PRIVATE_FUNC void chi_simd(__m256i state[25]) {
    __m256i B[25];
    int x, y;
    for (y = 0; y < 5; ++y) {
        B[0+5*y] = _mm256_xor_si256(state[0+5*y],
                    _mm256_andnot_si256(state[1+5*y], state[2+5*y]));
        B[1+5*y] = _mm256_xor_si256(state[1+5*y],
                    _mm256_andnot_si256(state[2+5*y], state[3+5*y]));
        B[2+5*y] = _mm256_xor_si256(state[2+5*y],
                    _mm256_andnot_si256(state[3+5*y], state[4+5*y]));
        B[3+5*y] = _mm256_xor_si256(state[3+5*y],
                    _mm256_andnot_si256(state[4+5*y], state[0+5*y]));
        B[4+5*y] = _mm256_xor_si256(state[4+5*y],
                    _mm256_andnot_si256(state[0+5*y], state[1+5*y]));
    }
    for (y = 0; y < 5; ++y)
        for (x = 0; x < 5; ++x)
            state[x+5*y] = B[x+5*y];
}

HASHA_PRIVATE_FUNC void iota_simd(__m256i state[25], int round) {
    __m256i rc = _mm256_set1_epi64x(SHA3_KECCAK_ROUND_CONSTANTS[round]);
    state[0] = _mm256_xor_si256(state[0], rc);
}

HASHA_PUBLIC_FUNC void keccak_permutation_simd(__m256i state[25]) {
    int round;
    for (round = 0; round < SHA3_KECCAK_ROUNDS; ++round) {
        theta_simd(state);
        rho_pi_simd(state);
        chi_simd(state);
        iota_simd(state, round);
    }
}

#endif  /* End of SIMD variant */


/*=============================================================================
   Variant 2: Nano Implementation (ARM NEON)
   Each state is represented as an array of 25 uint64x2_t values (2 lanes per vector).
   Unrolling and inlining is applied similar to the other variants.
  ===========================================================================*/
#if KECCAK_ACCELERATION == 2

#include <arm_neon.h>

static inline uint64x2_t ROTL64_nano(uint64x2_t x, int n) {
    return vorrq_u64(vshlq_n_u64(x, n),
                     vshrq_n_u64(x, 64 - n));
}

HASHA_PRIVATE_FUNC void theta_nano(uint64x2_t state[25]) {
    uint64x2_t C[5], D[5];
    int x, i;
    for (x = 0; x < 5; ++x) {
        C[x] = veorq_u64(state[x],
              veorq_u64(state[x+5],
              veorq_u64(state[x+10],
              veorq_u64(state[x+15], state[x+20]))));
    }
    for (x = 0; x < 5; ++x) {
        uint64x2_t t = ROTL64_nano(C[(x+1)%5], 1);
        D[x] = veorq_u64(C[(x+4)%5], t);
    }
    for (i = 0; i < 25; ++i) {
        state[i] = veorq_u64(state[i], D[i % 5]);
    }
}

HASHA_PRIVATE_FUNC void rho_pi_nano(uint64x2_t state[25]) {
    uint64x2_t B[25];
    int x, y;
    for (y = 0; y < 5; ++y) {
        for (x = 0; x < 5; ++x) {
            int index = x + 5*y;
            int newX = y;
            int newY = (2*x + 3*y) % 5;
            int newIndex = newX + 5*newY;
            int offset = SHA3_RHO_OFFSETS[x][y];
            B[newIndex] = ROTL64_nano(state[index], offset);
        }
    }
    for (x = 0; x < 25; ++x)
        state[x] = B[x];
}

HASHA_PRIVATE_FUNC void chi_nano(uint64x2_t state[25]) {
    uint64x2_t B[25];
    int x, y;
    for (y = 0; y < 5; ++y) {
        B[0+5*y] = veorq_u64(state[0+5*y],
                     vandq_u64(vmvnq_u64(state[1+5*y]), state[2+5*y]));
        B[1+5*y] = veorq_u64(state[1+5*y],
                     vandq_u64(vmvnq_u64(state[2+5*y]), state[3+5*y]));
        B[2+5*y] = veorq_u64(state[2+5*y],
                     vandq_u64(vmvnq_u64(state[3+5*y]), state[4+5*y]));
        B[3+5*y] = veorq_u64(state[3+5*y],
                     vandq_u64(vmvnq_u64(state[4+5*y]), state[0+5*y]));
        B[4+5*y] = veorq_u64(state[4+5*y],
                     vandq_u64(vmvnq_u64(state[0+5*y]), state[1+5*y]));
    }
    for (y = 0; y < 5; ++y)
        for (x = 0; x < 5; ++x)
            state[x+5*y] = B[x+5*y];
}

HASHA_PRIVATE_FUNC void iota_nano(uint64x2_t state[25], int round) {
    uint64x2_t rc = vdupq_n_u64(SHA3_KECCAK_ROUND_CONSTANTS[round]);
    state[0] = veorq_u64(state[0], rc);
}

HASHA_PUBLIC_FUNC void keccak_permutation_nano(uint64x2_t state[25]) {
    int round;
    for (round = 0; round < SHA3_KECCAK_ROUNDS; ++round) {
        theta_nano(state);
        rho_pi_nano(state);
        chi_nano(state);
        iota_nano(state, round);
    }
}

#endif  /* End of Nano variant */


/*=============================================================================
  Wrapper Function
  ----------------------------------------------------------------------------
  This function always accepts a pointer to 25 uint64_t words (a single
  Keccak state). It copies the state into the hardware vector type and calls
  the accelerated variant if enabled. Otherwise, it calls the software version.
  ----------------------------------------------------------------------------
  Note: Only the lowest lane of each vector is used to hold the input state,
  and only that lane is written back.
  ===========================================================================*/
HASHA_PUBLIC_FUNC
void keccak_permutation(uint64_t *state) {
#if KECCAK_ACCELERATION == 1
    // AVX2 variant: use __m256i (4 lanes per vector)
    __m256i simd_state[25];
    int i;
    for (i = 0; i < 25; i++) {
        // Initialize with state[i] in lane 0; other lanes are set to zero.
        simd_state[i] = _mm256_set_epi64x(0, 0, 0, state[i]);
    }
    keccak_permutation_simd(simd_state);
    for (i = 0; i < 25; i++) {
        // Extract lane 0; _mm256_extract_epi64 is used if available.
        state[i] = (uint64_t)_mm256_extract_epi64(simd_state[i], 0);
    }
#elif KECCAK_ACCELERATION == 2
    // NEON variant: use uint64x2_t (2 lanes per vector)
    uint64x2_t nano_state[25];
    int i;
    for (i = 0; i < 25; i++) {
        nano_state[i] = vdupq_n_u64(0);
        nano_state[i] = vsetq_lane_u64(state[i], nano_state[i], 0);
    }
    keccak_permutation_nano(nano_state);
    for (i = 0; i < 25; i++) {
        uint64_t tmp[2];
        vst1q_u64(tmp, nano_state[i]);
        state[i] = tmp[0];
    }
#else
    // Fall back to the software implementation
    keccak_permutation_software(state);
#endif
}