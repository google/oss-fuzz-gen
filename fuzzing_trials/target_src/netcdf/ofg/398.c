#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Function signature to be fuzzed
int nc_create_mem(const char *name, int mode, size_t size, int *ncid);

int LLVMFuzzerTestOneInput_398(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to extract meaningful input for the function
    if (size < sizeof(int) + sizeof(size_t) + 1) {
        return 0;
    }

    // Extract a string from the data
    size_t name_len = size - sizeof(int) - sizeof(size_t);
    char *name = (char *)malloc(name_len + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data, name_len);
    name[name_len] = '\0';  // Null-terminate the string

    // Extract an integer for mode
    int mode;
    memcpy(&mode, data + name_len, sizeof(int));

    // Extract a size_t for size
    size_t mem_size;
    memcpy(&mem_size, data + name_len + sizeof(int), sizeof(size_t));

    // Prepare an integer pointer for ncid
    int ncid = 0;

    // Call the function-under-test
    nc_create_mem(name, mode, mem_size, &ncid);

    // Clean up
    free(name);

    return 0;
}