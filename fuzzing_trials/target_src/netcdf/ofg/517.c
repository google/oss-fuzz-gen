#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

extern int nc_open_mem(const char *path, int mode, size_t size, void *memory, int *ncidp);

int LLVMFuzzerTestOneInput_517(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for creating a valid input
    if (size < 10) {
        return 0;
    }

    // Allocate memory for the inputs
    char *path = (char *)malloc(5);
    int mode = 0;
    size_t mem_size = size - 5;
    void *memory = malloc(mem_size);
    int ncid;

    // Initialize the inputs
    memcpy(path, data, 4);
    path[4] = '\0'; // Null-terminate the string
    memcpy(memory, data + 5, mem_size);

    // Call the function under test
    nc_open_mem(path, mode, mem_size, memory, &ncid);

    // Free allocated memory
    free(path);
    free(memory);

    return 0;
}