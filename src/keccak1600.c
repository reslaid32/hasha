
#define HASHA_LIBRARY_BUILD

#include "../include/hasha/keccak1600.h"

#include <stdint.h>

HASHA_PRIVATE_FUNC uint64_t rol64(uint64_t x, unsigned r) __attribute__((always_inline));
HASHA_PRIVATE_FUNC uint64_t rol64(uint64_t x, unsigned r) {
    return (x << r) | (x >> (64 - r));
}
 
// Macro that unrolls one round of Keccak-f[1600] with all steps inlined.
#define KECCAKF_ROUND(state, rc) do {                                    \
    /* Theta step */                                                     \
    uint64_t C0 = state[0] ^ state[5]  ^ state[10] ^ state[15] ^ state[20];     \
    uint64_t C1 = state[1] ^ state[6]  ^ state[11] ^ state[16] ^ state[21];     \
    uint64_t C2 = state[2] ^ state[7]  ^ state[12] ^ state[17] ^ state[22];     \
    uint64_t C3 = state[3] ^ state[8]  ^ state[13] ^ state[18] ^ state[23];     \
    uint64_t C4 = state[4] ^ state[9]  ^ state[14] ^ state[19] ^ state[24];     \
    uint64_t D0 = rol64(C1, 1) ^ C4;                                            \
    uint64_t D1 = rol64(C2, 1) ^ C0;                                            \
    uint64_t D2 = rol64(C3, 1) ^ C1;                                            \
    uint64_t D3 = rol64(C4, 1) ^ C2;                                            \
    uint64_t D4 = rol64(C0, 1) ^ C3;                                            \
    state[0]  ^= D0; state[1]  ^= D1; state[2]  ^= D2; state[3]  ^= D3; state[4]  ^= D4;  \
    state[5]  ^= D0; state[6]  ^= D1; state[7]  ^= D2; state[8]  ^= D3; state[9]  ^= D4;  \
    state[10] ^= D0; state[11] ^= D1; state[12] ^= D2; state[13] ^= D3; state[14] ^= D4;  \
    state[15] ^= D0; state[16] ^= D1; state[17] ^= D2; state[18] ^= D3; state[19] ^= D4;  \
    state[20] ^= D0; state[21] ^= D1; state[22] ^= D2; state[23] ^= D3; state[24] ^= D4;  \
                                                                         \
    /* Rho and Pi steps */                                               \
    uint64_t B0  = state[0];                                                  \
    uint64_t B1  = rol64(state[6],  44);                                       \
    uint64_t B2  = rol64(state[12], 43);                                       \
    uint64_t B3  = rol64(state[18], 21);                                       \
    uint64_t B4  = rol64(state[24], 14);                                       \
    uint64_t B5  = rol64(state[3],  28);                                       \
    uint64_t B6  = rol64(state[9],  20);                                       \
    uint64_t B7  = rol64(state[10], 3);                                        \
    uint64_t B8  = rol64(state[16], 45);                                       \
    uint64_t B9  = rol64(state[22], 61);                                       \
    uint64_t B10 = rol64(state[1],  1);                                        \
    uint64_t B11 = rol64(state[7],  6);                                        \
    uint64_t B12 = rol64(state[13], 25);                                       \
    uint64_t B13 = rol64(state[19], 8);                                        \
    uint64_t B14 = rol64(state[20], 18);                                       \
    uint64_t B15 = rol64(state[4],  27);                                       \
    uint64_t B16 = rol64(state[5],  36);                                       \
    uint64_t B17 = rol64(state[11], 10);                                       \
    uint64_t B18 = rol64(state[17], 15);                                       \
    uint64_t B19 = rol64(state[23], 56);                                       \
    uint64_t B20 = rol64(state[2],  62);                                       \
    uint64_t B21 = rol64(state[8],  55);                                       \
    uint64_t B22 = rol64(state[14], 39);                                       \
    uint64_t B23 = rol64(state[15], 41);                                       \
    uint64_t B24 = rol64(state[21], 2);                                        \
                                                                         \
    /* Chi step */                                                       \
    state[0]  = B0  ^ ((~B1)  & B2);                                       \
    state[1]  = B1  ^ ((~B2)  & B3);                                       \
    state[2]  = B2  ^ ((~B3)  & B4);                                       \
    state[3]  = B3  ^ ((~B4)  & B0);                                       \
    state[4]  = B4  ^ ((~B0)  & B1);                                       \
    state[5]  = B5  ^ ((~B6)  & B7);                                       \
    state[6]  = B6  ^ ((~B7)  & B8);                                       \
    state[7]  = B7  ^ ((~B8)  & B9);                                       \
    state[8]  = B8  ^ ((~B9)  & B5);                                       \
    state[9]  = B9  ^ ((~B5)  & B6);                                       \
    state[10] = B10 ^ ((~B11) & B12);                                      \
    state[11] = B11 ^ ((~B12) & B13);                                      \
    state[12] = B12 ^ ((~B13) & B14);                                      \
    state[13] = B13 ^ ((~B14) & B10);                                      \
    state[14] = B14 ^ ((~B10) & B11);                                      \
    state[15] = B15 ^ ((~B16) & B17);                                      \
    state[16] = B16 ^ ((~B17) & B18);                                      \
    state[17] = B17 ^ ((~B18) & B19);                                      \
    state[18] = B18 ^ ((~B19) & B15);                                      \
    state[19] = B19 ^ ((~B15) & B16);                                      \
    state[20] = B20 ^ ((~B21) & B22);                                      \
    state[21] = B21 ^ ((~B22) & B23);                                      \
    state[22] = B22 ^ ((~B23) & B24);                                      \
    state[23] = B23 ^ ((~B24) & B20);                                      \
    state[24] = B24 ^ ((~B20) & B21);                                      \
                                                                         \
    /* Iota step */                                                      \
    state[0] ^= rc;                                                      \
} while(0)
 
HASHA_PUBLIC_FUNC void keccakf1600(uint64_t * restrict state) {
    KECCAKF_ROUND(state, 0x0000000000000001ULL);
    KECCAKF_ROUND(state, 0x0000000000008082ULL);
    KECCAKF_ROUND(state, 0x800000000000808aULL);
    KECCAKF_ROUND(state, 0x8000000080008000ULL);
    KECCAKF_ROUND(state, 0x000000000000808bULL);
    KECCAKF_ROUND(state, 0x0000000080000001ULL);
    KECCAKF_ROUND(state, 0x8000000080008081ULL);
    KECCAKF_ROUND(state, 0x8000000000008009ULL);
    KECCAKF_ROUND(state, 0x000000000000008aULL);
    KECCAKF_ROUND(state, 0x0000000000000088ULL);
    KECCAKF_ROUND(state, 0x0000000080008009ULL);
    KECCAKF_ROUND(state, 0x000000008000000aULL);
    KECCAKF_ROUND(state, 0x000000008000808bULL);
    KECCAKF_ROUND(state, 0x800000000000008bULL);
    KECCAKF_ROUND(state, 0x8000000000008089ULL);
    KECCAKF_ROUND(state, 0x8000000000008003ULL);
    KECCAKF_ROUND(state, 0x8000000000008002ULL);
    KECCAKF_ROUND(state, 0x8000000000000080ULL);
    KECCAKF_ROUND(state, 0x000000000000800aULL);
    KECCAKF_ROUND(state, 0x800000008000000aULL);
    KECCAKF_ROUND(state, 0x8000000080008081ULL);
    KECCAKF_ROUND(state, 0x8000000000008080ULL);
    KECCAKF_ROUND(state, 0x0000000080000001ULL);
    KECCAKF_ROUND(state, 0x8000000080008008ULL);
}

#if 0
#if defined(__clang__)
HASHA_PUBLIC_FUNC void keccakf1600_clang_vectorized(_vec200_u64 *state)
{
    KECCAKF_ROUND((*state), 0x0000000000000001ULL);
    KECCAKF_ROUND((*state), 0x0000000000008082ULL);
    KECCAKF_ROUND((*state), 0x800000000000808aULL);
    KECCAKF_ROUND((*state), 0x8000000080008000ULL);
    KECCAKF_ROUND((*state), 0x000000000000808bULL);
    KECCAKF_ROUND((*state), 0x0000000080000001ULL);
    KECCAKF_ROUND((*state), 0x8000000080008081ULL);
    KECCAKF_ROUND((*state), 0x8000000000008009ULL);
    KECCAKF_ROUND((*state), 0x000000000000008aULL);
    KECCAKF_ROUND((*state), 0x0000000000000088ULL);
    KECCAKF_ROUND((*state), 0x0000000080008009ULL);
    KECCAKF_ROUND((*state), 0x000000008000000aULL);
    KECCAKF_ROUND((*state), 0x000000008000808bULL);
    KECCAKF_ROUND((*state), 0x800000000000008bULL);
    KECCAKF_ROUND((*state), 0x8000000000008089ULL);
    KECCAKF_ROUND((*state), 0x8000000000008003ULL);
    KECCAKF_ROUND((*state), 0x8000000000008002ULL);
    KECCAKF_ROUND((*state), 0x8000000000000080ULL);
    KECCAKF_ROUND((*state), 0x000000000000800aULL);
    KECCAKF_ROUND((*state), 0x800000008000000aULL);
    KECCAKF_ROUND((*state), 0x8000000080008081ULL);
    KECCAKF_ROUND((*state), 0x8000000000008080ULL);
    KECCAKF_ROUND((*state), 0x0000000080000001ULL);
    KECCAKF_ROUND((*state), 0x8000000080008008ULL);
}
#endif
#endif