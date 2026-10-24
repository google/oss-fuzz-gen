#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "libbpf.h"
#include "/src/libbpf/src/bpf.h" // Include the header for bpf related functions

int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    // Create a bpf_object to hold the program
    struct bpf_object *obj = bpf_object__open_mem(data, size, NULL);
    if (!obj) {
        return 0;
    }

    // Load the BPF object
    if (bpf_object__load(obj) != 0) {
        bpf_object__close(obj);
        return 0;
    }

    // Find a program within the object
    struct bpf_program *prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        bpf_object__close(obj);
        return 0;
    }

    // Declare and initialize bpf_netfilter_opts struct
    struct bpf_netfilter_opts opts;
    opts.sz = sizeof(struct bpf_netfilter_opts);
    opts.flags = 0; // Set flags to 0 or any other valid value

    // Call the function under test
    struct bpf_link *link = bpf_program__attach_netfilter(prog, &opts);

    // Clean up if necessary (e.g., detach link)
    if (link != NULL) {
        bpf_link__destroy(link);
    }

    // Close the bpf_object
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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
