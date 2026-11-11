#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Function-under-test declaration
int nc_inq_grpname_full(int, size_t *, char *);

// Fuzzing harness
int LLVMFuzzerTestOneInput_78(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract meaningful inputs
    if (size < sizeof(int) + sizeof(size_t)) {
        return 0;
    }

    // Extract an integer from the input data
    int int_param;
    memcpy(&int_param, data, sizeof(int));

    // Extract a size_t from the input data
    size_t size_param;
    memcpy(&size_param, data + sizeof(int), sizeof(size_t));

    // Ensure the rest of the data is used as a string
    size_t remaining_size = size - sizeof(int) - sizeof(size_t);
    char *char_param = (char *)malloc(remaining_size + 1);
    if (char_param == NULL) {
        return 0;
    }
    memcpy(char_param, data + sizeof(int) + sizeof(size_t), remaining_size);
    char_param[remaining_size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    nc_inq_grpname_full(int_param, &size_param, char_param);

    // Clean up
    free(char_param);

    return 0;
}