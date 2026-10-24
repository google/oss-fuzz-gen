#include <stddef.h>
#include <stdint.h>
#include "/src/libbpf/src/libbpf.h"

int LLVMFuzzerTestOneInput_120(const uint8_t *data, size_t size) {
    struct bpf_object *bpf_obj;
    unsigned int kversion;

    // Initialize the BPF object from the input data
    bpf_obj = bpf_object__open_mem(data, size, NULL);
    if (!bpf_obj) {
        return 0; // If the object cannot be opened, return early
    }

    // Call the function-under-test
    kversion = bpf_object__kversion(bpf_obj);

    // Clean up the BPF object
    bpf_object__close(bpf_obj);

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

    LLVMFuzzerTestOneInput_120(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
