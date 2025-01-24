#define HASHA_LIBRARY_BUILD

#include "../include/hasha/sha3_keccak.h"

HASHA_EXPORT HASHA_INLINE void sha3_keccak_permutation(uint64_t *state) {
    for (int round = 0; round < SHA3_KECCAK_ROUNDS; ++round) {
        uint64_t C[5], D[5], B[5][5];

        // Theta step
        for (int x = 0; x < 5; ++x) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for (int x = 0; x < 5; ++x) {
            D[x] = C[(x + 4) % 5] ^ ((C[(x + 1) % 5] << 1) | (C[(x + 1) % 5] >> (64 - 1)));
            for (int y = 0; y < 5; ++y) {
                state[x + y * 5] ^= D[x];
            }
        }

        // Rho and Pi steps
        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                B[y][(2 * x + 3 * y) % 5] = (state[x + y * 5] << SHA3_RHO_OFFSETS[x][y]) | (state[x + y * 5] >> (64 - SHA3_RHO_OFFSETS[x][y]));
            }
        }

        // Chi step
        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                state[x + y * 5] = B[x][y] ^ (~B[(x + 1) % 5][y] & B[(x + 2) % 5][y]);
            }
        }

        // Iota step
        state[0] ^= SHA3_KECCAK_ROUND_CONSTANTS[round];
    }
}