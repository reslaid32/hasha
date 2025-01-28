#define HASHA_LIBRARY_BUILD

#include "../include/hasha/keccak_perm.h"

HASHA_PRIVATE_FUNC void theta(uint64_t *state) {
    uint64_t C[5], D[5];
    
    // Step 1: Calculate C[x] with loop unrolling
    C[0] = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
    C[1] = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
    C[2] = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
    C[3] = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
    C[4] = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

    // Step 2: Calculate D[x] with loop unrolling
    D[0] = C[4] ^ ((C[1] << 1) | (C[1] >> 63));
    D[1] = C[0] ^ ((C[2] << 1) | (C[2] >> 63));
    D[2] = C[1] ^ ((C[3] << 1) | (C[3] >> 63));
    D[3] = C[2] ^ ((C[4] << 1) | (C[4] >> 63));
    D[4] = C[3] ^ ((C[0] << 1) | (C[0] >> 63));

    // Step 3: Update state with loop unrolling
    state[0] ^= D[0];
    state[5] ^= D[0];
    state[10] ^= D[0];
    state[15] ^= D[0];
    state[20] ^= D[0];

    state[1] ^= D[1];
    state[6] ^= D[1];
    state[11] ^= D[1];
    state[16] ^= D[1];
    state[21] ^= D[1];

    state[2] ^= D[2];
    state[7] ^= D[2];
    state[12] ^= D[2];
    state[17] ^= D[2];
    state[22] ^= D[2];

    state[3] ^= D[3];
    state[8] ^= D[3];
    state[13] ^= D[3];
    state[18] ^= D[3];
    state[23] ^= D[3];

    state[4] ^= D[4];
    state[9] ^= D[4];
    state[14] ^= D[4];
    state[19] ^= D[4];
    state[24] ^= D[4];
}

HASHA_PRIVATE_FUNC void rho_pi(uint64_t *state) {
    uint64_t B[5][5];
    
    // Process all rows in a single pass
    for (int x = 0; x < 5; ++x) {
        for (int y = 0; y < 5; ++y) {
            int offset = SHA3_RHO_OFFSETS[x][y];
            uint64_t value = state[x + y * 5];
            B[y][(2 * x + 3 * y) % 5] = (value << offset) | (value >> (64 - offset));
        }
    }

    // Directly write results back to state with unrolled loop
    // Writing in a single pass, with both inner and outer loops collapsed
    for (int x = 0; x < 5; ++x) {
        state[x + 0 * 5] = B[x][0];
        state[x + 1 * 5] = B[x][1];
        state[x + 2 * 5] = B[x][2];
        state[x + 3 * 5] = B[x][3];
        state[x + 4 * 5] = B[x][4];
    }
}

HASHA_PRIVATE_FUNC void chi(uint64_t *state) {
    uint64_t B[5][5];

    // Unrolling the x loop (5 iterations)
    for (int x = 0; x < 5; ++x) {
        // Unrolling the y loop (5 iterations)
        B[x][0] = state[x + 0 * 5] ^ (~state[(x + 1) % 5 + 0 * 5] & state[(x + 2) % 5 + 0 * 5]);
        B[x][1] = state[x + 1 * 5] ^ (~state[(x + 1) % 5 + 1 * 5] & state[(x + 2) % 5 + 1 * 5]);
        B[x][2] = state[x + 2 * 5] ^ (~state[(x + 1) % 5 + 2 * 5] & state[(x + 2) % 5 + 2 * 5]);
        B[x][3] = state[x + 3 * 5] ^ (~state[(x + 1) % 5 + 3 * 5] & state[(x + 2) % 5 + 3 * 5]);
        B[x][4] = state[x + 4 * 5] ^ (~state[(x + 1) % 5 + 4 * 5] & state[(x + 2) % 5 + 4 * 5]);
    }

    // Unrolling the assignment back to the state
    for (int x = 0; x < 5; ++x) {
        state[x + 0 * 5] = B[x][0];
        state[x + 1 * 5] = B[x][1];
        state[x + 2 * 5] = B[x][2];
        state[x + 3 * 5] = B[x][3];
        state[x + 4 * 5] = B[x][4];
    }
}

HASHA_PRIVATE_FUNC void iota(uint64_t *state, int round) {
    state[0] ^= SHA3_KECCAK_ROUND_CONSTANTS[round];
}

HASHA_PUBLIC_FUNC void keccak_permutation(uint64_t *state) {
    for (int round = 0; round < SHA3_KECCAK_ROUNDS; ++round) {
        theta(state);
        rho_pi(state);
        chi(state);
        iota(state, round);
    }
}