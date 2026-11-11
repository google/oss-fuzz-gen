#include <stdint.h>
#include <stddef.h>
#include "/src/libbpf/src/libbpf.h"

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    struct bpf_program *prog;

    // Check if the size is non-zero to ensure we have some data to work with.
    if (size == 0) {
        return 0;
    }

    // Initialize the bpf_program structure using the provided data.
    // Since we can't use sizeof(struct bpf_program), we just check if size is non-zero.
    prog = (struct bpf_program *)data;

    // Call the function under test.
    __u32 func_info_count = bpf_program__func_info_cnt(prog);

    // Use the result to avoid any compiler optimizations that might skip the function call.
    (void)func_info_count;

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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
