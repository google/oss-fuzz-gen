#include <stdint.h>
#include <stddef.h>
#include <linux/bpf.h> // Include the correct header for BPF types
#include "/src/libbpf/src/libbpf.h"

// Function-under-test signature
// Use the correct enum type from the included bpf.h
int libbpf_probe_bpf_prog_type(enum bpf_prog_type prog_type, const void *opts);

int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to extract the required inputs
    if (size < sizeof(enum bpf_prog_type)) {
        return 0;
    }

    // Extract the bpf_prog_type from the data
    enum bpf_prog_type prog_type = *(enum bpf_prog_type *)data;

    // Use the remaining data as the opts parameter
    const void *opts = (const void *)(data + sizeof(enum bpf_prog_type));

    // Call the function-under-test
    libbpf_probe_bpf_prog_type(prog_type, opts);

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

    LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
