#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming nc_create_mem is declared elsewhere and linked appropriately
extern int nc_create_mem(const char *name, int mode, size_t size, int *ncid);

int LLVMFuzzerTestOneInput_399(const uint8_t *data, size_t size) {
    // Ensure there's enough data to extract meaningful inputs
    if (size < sizeof(int) + sizeof(size_t) + 1) {
        return 0;
    }

    // Calculate the maximum possible length for the name string
    size_t name_length = size - sizeof(int) - sizeof(size_t);
    
    // Ensure null-termination for the name string
    char *name = (char *)malloc(name_length + 1);
    if (!name) {
        return 0;
    }
    memcpy(name, data, name_length);
    name[name_length] = '\0';

    // Extract inputs from the fuzzing data
    int mode = *((int *)(data + size - sizeof(int)));
    size_t mem_size = *((size_t *)(data + size - sizeof(int) - sizeof(size_t)));
    int ncid;

    // Call the function-under-test
    nc_create_mem(name, mode, mem_size, &ncid);

    // Free allocated memory
    free(name);

    return 0;
}