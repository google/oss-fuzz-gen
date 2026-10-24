#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "/src/libbpf/src/libbpf.h"

int LLVMFuzzerTestOneInput_100(const uint8_t *data, size_t size) {
    struct bpf_program *prog = NULL;
    struct bpf_object *obj = NULL;
    int err;
    
    // Create a temporary BPF object from the input data
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

    // Iterate over BPF programs in the object
    bpf_object__for_each_program(prog, obj) {
        // Call the function-under-test
        size_t insn_count = bpf_program__insn_cnt(prog);
        (void)insn_count; // Suppress unused variable warning
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_100(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
