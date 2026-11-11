#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h> // Include string.h for memcpy

// Assuming the definition of struct bpf_map is available
struct bpf_map {
    int dummy; // Placeholder for actual struct members
};

// Declaration of the function-under-test
bool bpf_map__is_pinned(const struct bpf_map *);

// Remove the extern "C" linkage specification as it is not applicable in C
int LLVMFuzzerTestOneInput_94(const uint8_t *data, size_t size) {
    // Initialize a bpf_map structure
    struct bpf_map map;
    
    // Ensure the data is not empty and is large enough to fill the struct
    if (size >= sizeof(map)) {
        // Copy data into the map structure to simulate different inputs
        memcpy(&map, data, sizeof(map));
    } else {
        // If not enough data, initialize with some default non-zero values
        map.dummy = 1;
    }

    // Call the function-under-test
    bool result = bpf_map__is_pinned(&map);

    // Use the result to avoid any compiler optimizations that skip the call
    volatile bool avoid_optimization = result;

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_94(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
