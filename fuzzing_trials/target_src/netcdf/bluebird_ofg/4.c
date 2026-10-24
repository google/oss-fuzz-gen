#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int nc__create(const char *path, int mode, size_t size, size_t *created_size, int *status);

int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract meaningful parameters
    if (size < sizeof(int) + sizeof(size_t) + sizeof(int)) {
        return 0;
    }

    // Extract parameters from input data
    const char *path = "/tmp/fuzzfile"; // Use a fixed path for testing
    int mode = *((int *)data);
    size_t input_size = *((size_t *)(data + sizeof(int)));
    size_t created_size = 0;
    int status = 0;

    // Call the function-under-test

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of nc__create
    nc__create(path, mode, size, &created_size, &status);
    // End mutation: Producer.REPLACE_ARG_MUTATOR



    return 0;
}