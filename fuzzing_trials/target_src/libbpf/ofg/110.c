#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libbpf/src/libbpf.h" // Correct path for libbpf.h
#include "/src/libbpf/src/bpf.h"    // Include the header where struct bpf_program is fully defined

int LLVMFuzzerTestOneInput_110(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    struct bpf_program *prog = NULL;
    struct bpf_object *obj = NULL;
    int ifindex = 1; // Assuming a valid interface index for testing

    // Open a BPF object from the data
    obj = bpf_object__open_mem(data, size, NULL);
    if (!obj) {
        return 0;
    }

    // Load the BPF object
    if (bpf_object__load(obj) < 0) {
        bpf_object__close(obj);
        return 0;
    }

    // Get the first program in the BPF object
    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        bpf_object__close(obj);
        return 0;
    }

    // Call the function-under-test
    struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);

    // Clean up
    if (link != NULL) {
        bpf_link__destroy(link);
    }
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

    LLVMFuzzerTestOneInput_110(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
