#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Assuming the function gdbm_version_cmp is declared somewhere
int gdbm_version_cmp(const int *, const int *);

int LLVMFuzzerTestOneInput_105(const uint8_t *data, size_t size) {
    if (size < 2 * sizeof(int)) {
        // Not enough data to extract two integers
        return 0;
    }

    // Extract two integers from the input data
    int version1 = *(const int *)(data);
    int version2 = *(const int *)(data + sizeof(int));

    // Call the function-under-test
    gdbm_version_cmp(&version1, &version2);

    return 0;
}