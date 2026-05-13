#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Assuming mkfilename is defined elsewhere
extern char *mkfilename(const char *, const char *, const char *);

int LLVMFuzzerTestOneInput_120(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to split into three parts
    if (size < 3) return 0;

    // Split the input data into three parts
    size_t part1_size = size / 3;
    size_t part2_size = size / 3;
    size_t part3_size = size - part1_size - part2_size;

    // Allocate memory for the strings and ensure null-termination
    char *part1 = (char *)malloc(part1_size + 1);
    char *part2 = (char *)malloc(part2_size + 1);
    char *part3 = (char *)malloc(part3_size + 1);

    if (!part1 || !part2 || !part3) {
        free(part1);
        free(part2);
        free(part3);
        return 0;
    }

    memcpy(part1, data, part1_size);
    memcpy(part2, data + part1_size, part2_size);
    memcpy(part3, data + part1_size + part2_size, part3_size);

    part1[part1_size] = '\0';
    part2[part2_size] = '\0';
    part3[part3_size] = '\0';

    // Call the function-under-test
    char *result = mkfilename(part1, part2, part3);

    // Free allocated memory
    free(part1);
    free(part2);
    free(part3);

    // Free the result if it was dynamically allocated
    free(result);

    return 0;
}