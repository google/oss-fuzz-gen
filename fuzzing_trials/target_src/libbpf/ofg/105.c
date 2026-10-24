#include <stdint.h>
#include <stddef.h>
#include <linux/bpf.h> // Include the header where enum bpf_map_type is defined
#include "/src/libbpf/src/libbpf.h"

int LLVMFuzzerTestOneInput_105(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for the test
    if (size < sizeof(enum bpf_map_type)) {
        return 0;
    }

    // Prepare the map type from the input data
    enum bpf_map_type map_type = (enum bpf_map_type)(data[0] % 3); // Assuming 3 map types

    // Call the function-under-test
    libbpf_probe_bpf_map_type(map_type, (const void *)(data + 1));

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

    LLVMFuzzerTestOneInput_105(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
