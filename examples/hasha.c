#include "../include/hasha/ver.h"
#include "../include/hasha/acel.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>

const char *stringize_acel_status(int acel) {
    switch (acel) {
        case 1:     return "SIMD";
        case 2:     return "Neon";
        default:    return "Disabled";
    }
}

int in_range(int x, int min, int max) {
    if (min > max) {
        int tmp = min;
        min = max;
        max = tmp;
    }
    return (x >= min && x <= max);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        goto usage;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            hashaver_t hashav = hashaver();
            printf("libhasha version: %u.%u.%u\n", hashav.major, hashav.minor, hashav.patch);
            return EXIT_SUCCESS;
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--accelerating") == 0) {
            int hashac = hashacel();
            printf("libhasha accelerating status: %0x (%s)\n", hashac, stringize_acel_status(hashac));
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
