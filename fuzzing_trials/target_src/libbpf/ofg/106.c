#include <stdint.h>
#include <stddef.h>
#include "/src/libbpf/src/libbpf.h"
#include "/src/libbpf/src/bpf.h"
#include "/src/libbpf/include/uapi/linux/bpf.h"

int LLVMFuzzerTestOneInput_106(const uint8_t *data, size_t size) {
    struct bpf_program *prog;
    struct bpf_object *obj;
    int err;
    
    if (size < sizeof(struct bpf_insn)) {
        return 0;
    }

    // Load a BPF object from the data
    obj = bpf_object__open_mem(data, size, NULL);
    if (!obj) {
        return 0;
    }

    // Load BPF program within the object
    err = bpf_object__load(obj);
    if (err) {
        bpf_object__close(obj);
        return 0;
    }

    // Get the first BPF program
    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        bpf_object__close(obj);
        return 0;
    }

    // Call the function-under-test
    const struct bpf_insn *insns = bpf_program__insns(prog);

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

    LLVMFuzzerTestOneInput_106(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
