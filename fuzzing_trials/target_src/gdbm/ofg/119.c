#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Function-under-test declaration
char *mkfilename(const char *, const char *, const char *);

// LLVMFuzzerTestOneInput function definition
int LLVMFuzzerTestOneInput_119(const uint8_t *data, size_t size) {
    // Ensure the input size is large enough to split into three parts
    if (size < 3) {
        return 0;
    }

    // Calculate the length of each part
    size_t part_len = size / 3;
    size_t remainder = size % 3;

    // Allocate memory for each string part and ensure they are null-terminated
    char *part1 = (char *)malloc(part_len + 1);
    char *part2 = (char *)malloc(part_len + 1);
    char *part3 = (char *)malloc(part_len + remainder + 1);

    if (!part1 || !part2 || !part3) {
        // If memory allocation fails, clean up and return
        free(part1);
        free(part2);
        free(part3);
        return 0;
    }

    // Copy data into each part and null-terminate
    memcpy(part1, data, part_len);
    part1[part_len] = '\0';

    memcpy(part2, data + part_len, part_len);
    part2[part_len] = '\0';

    memcpy(part3, data + 2 * part_len, part_len + remainder);
    part3[part_len + remainder] = '\0';

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