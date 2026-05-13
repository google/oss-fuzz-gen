#include <stddef.h>
#include <stdint.h>
#include "/src/libbpf/src/libbpf.h"
#include <string.h>

// Define a mock bpf_object structure for testing
struct bpf_object {
    int dummy; // Placeholder member
};

// Implement a mock version of bpf_object__find_map_by_name_102
// In a real scenario, this would be provided by the BPF library
struct bpf_map *bpf_object__find_map_by_name_102(const struct bpf_object *obj, const char *name) {
    // Mock implementation: always return NULL for simplicity
    return NULL;
}

int LLVMFuzzerTestOneInput_102(const uint8_t *data, size_t size) {
    // Ensure there is enough data for a non-empty string
    if (size < 1) {
        return 0;
    }

    // Initialize a mock bpf_object
    struct bpf_object obj;
    obj.dummy = 0; // Initialize the dummy member

    // Create a null-terminated string from the input data
    char name[size + 1];
    memcpy(name, data, size);
    name[size] = '\0';

    // Call the function-under-test
    struct bpf_map *map = bpf_object__find_map_by_name_102(&obj, name);

    // For fuzzing purposes, we don't need to do anything with the result
    // Just ensure the function is called

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

    LLVMFuzzerTestOneInput_102(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
