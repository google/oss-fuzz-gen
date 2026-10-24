#include <stddef.h>
#include <stdint.h>
#include "/src/libbpf/src/libbpf.h"
#include "/src/libbpf/src/bpf.h"
#include "/src/libbpf/include/uapi/linux/bpf.h"
#include <stdlib.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
    struct bpf_program *prog = NULL;
    struct bpf_func_info *func_info = NULL;

    // Initialize a BPF object
    struct bpf_object *obj = bpf_object__open_mem(data, size, NULL);
    if (!obj) {
        return 0;
    }

    // Load the BPF object
    if (bpf_object__load(obj) != 0) {
        bpf_object__close(obj);
        return 0;
    }

    // Retrieve the first program from the BPF object
    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        bpf_object__close(obj);
        return 0;
    }

    // Call the function-under-test
    func_info = bpf_program__func_info(prog);

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

    LLVMFuzzerTestOneInput_101(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
