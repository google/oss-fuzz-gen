#include <sys/stat.h>
#include <string.h>
#include "libbpf.h"
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    struct bpf_object *obj = NULL;
    int err;

    // Create a BPF object from the provided data
    obj = bpf_object__open_mem(data, size, NULL);
    if (!obj) {
        return 0;
    }

    // Load the BPF object
    err = bpf_object__load(obj);
    if (err) {
        bpf_object__close(obj);
        return 0;
    }

    // Get the first program in the object
    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        bpf_object__close(obj);
        return 0;
    }

    // Attempt to attach the BPF program
    link = bpf_program__attach(prog);

    // Clean up
    if (link) {
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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
