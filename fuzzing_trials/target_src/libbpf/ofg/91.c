#include <stddef.h>
#include <stdint.h>
#include "/src/libbpf/src/bpf.h"
#include "/src/libbpf/include/uapi/linux/bpf.h"
#include "/src/libbpf/src/libbpf.h"

int LLVMFuzzerTestOneInput_91(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract a valid bpf_map_type value
    if (size < sizeof(enum bpf_map_type)) {
        return 0;
    }

    // Cast the input data to an enum bpf_map_type
    enum bpf_map_type map_type = *(enum bpf_map_type *)data;

    // Call the function-under-test
    const char *result = libbpf_bpf_map_type_str(map_type);

    // Optionally, you can print the result for debugging purposes
    // printf("Map type: %d, String: %s\n", map_type, result);

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

    LLVMFuzzerTestOneInput_91(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
