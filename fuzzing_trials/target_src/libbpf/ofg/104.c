#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// Assuming DW_TAG_enumeration_typebpf_map_type is an enum or typedef, 
// it should be defined somewhere in the headers or the codebase.
typedef enum {
    BPF_MAP_TYPE_UNSPEC,
    BPF_MAP_TYPE_HASH,
    BPF_MAP_TYPE_ARRAY,
    // Add other map types as defined in the actual codebase
    BPF_MAP_TYPE_MAX
} DW_TAG_enumeration_typebpf_map_type;

// Function signature as given
int libbpf_probe_bpf_map_type(DW_TAG_enumeration_typebpf_map_type map_type, const void *info);

// Fuzzing harness
int LLVMFuzzerTestOneInput_104(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for extracting an enum value
    if (size < sizeof(DW_TAG_enumeration_typebpf_map_type)) {
        return 0;
    }

    // Extract the map type from the input data
    DW_TAG_enumeration_typebpf_map_type map_type = (DW_TAG_enumeration_typebpf_map_type)(data[0] % BPF_MAP_TYPE_MAX);

    // Use the rest of the data as the void pointer info
    const void *info = (const void *)(data + 1);

    // Call the function-under-test
    int result = libbpf_probe_bpf_map_type(map_type, info);

    // Optionally, print the result for debugging purposes
    printf("Result: %d\n", result);

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

    LLVMFuzzerTestOneInput_104(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
