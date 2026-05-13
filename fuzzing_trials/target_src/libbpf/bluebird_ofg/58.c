#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "libbpf.h" // Include the correct header for libbpf

int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size) {
    // Open a BPF object from the input data
    struct bpf_object *obj = bpf_object__open_mem(data, size, NULL);
    if (!obj) {
        // If opening fails, return early
        return 0;
    }

    struct bpf_map *prev_map = NULL; // Initialize previous map as NULL

    // Call the function-under-test
    struct bpf_map *next_map = bpf_object__next_map(obj, prev_map);

    // Use next_map in a way that prevents compiler optimizations
    if (next_map) {
        // Access some field or perform some operation to ensure next_map is used
        (void)bpf_map__fd(next_map);
    }

    // Clean up and close the BPF object
    bpf_object__close(obj);

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

    LLVMFuzzerTestOneInput_58(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
