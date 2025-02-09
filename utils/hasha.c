#include "../include/hasha/internal/ver.h"
#include "../include/hasha/internal/acel.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

const char *stringize_acel_status(int acel) {
    switch (acel) {
        case 0:     return "Disabled";
        case 1:     return "SIMD";
        case 2:     return "Neon";
        default:    return "?";
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        goto usage;
    }
    
    hashaver_t hashav = hashaver();

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("libhasha version: %u.%u.%u\n", hashav.major, hashav.minor, hashav.patch);
            return EXIT_SUCCESS;
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--accelerating") == 0) {
            int hashac = hashacel();
            printf("libhasha hw accelerating: %s [%s (0x%0x)]\n", hashac ? "true" : "false", stringize_acel_status(hashac), hashac);
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            goto usage;
        }
    }

    return EXIT_SUCCESS;

    usage:
        fprintf(stderr, "Usage: %s [-v|--version] [-a|--accelerating]\n", argv[0]);
        return EXIT_FAILURE;
}
