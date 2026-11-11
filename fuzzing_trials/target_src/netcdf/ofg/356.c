#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int nc_inq_path(int, size_t *, char *);

int LLVMFuzzerTestOneInput_356(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract meaningful values
    if (size < sizeof(int) + sizeof(size_t) + 1) {
        return 0;
    }

    // Extract an integer from the data
    int int_param;
    memcpy(&int_param, data, sizeof(int));
    data += sizeof(int);
    size -= sizeof(int);

    // Extract a size_t from the data
    size_t size_param;
    memcpy(&size_param, data, sizeof(size_t));
    data += sizeof(size_t);
    size -= sizeof(size_t);

    // Allocate memory for the char array
    char *char_param = (char *)malloc(size + 1);
    if (char_param == NULL) {
        return 0;
    }

    // Copy remaining data into the char array and ensure null-termination
    memcpy(char_param, data, size);
    char_param[size] = '\0';

    // Call the function under test
    nc_inq_path(int_param, &size_param, char_param);

    // Free allocated memory
    free(char_param);

    return 0;
}