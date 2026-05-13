#include <stdint.h>
#include <stddef.h>
#include "/src/libbpf/src/libbpf.h"

int LLVMFuzzerTestOneInput_75(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient for the parameters
    if (size < sizeof(enum bpf_prog_type) + 
               sizeof(enum bpf_func_id) + 
               sizeof(void *)) {
        return 0;
    }

    // Extract the first part of data as enum bpf_prog_type
    enum bpf_prog_type prog_type = 
        *(enum bpf_prog_type *)data;

    // Extract the next part of data as enum bpf_func_id
    enum bpf_func_id func_id = 
        *(enum bpf_func_id *)(data + sizeof(enum bpf_prog_type));

    // Use the rest of the data as a dummy pointer
    const void *dummy_ptr = (const void *)(data + sizeof(enum bpf_prog_type) + 
                                           sizeof(enum bpf_func_id));

    // Call the function-under-test
    int result = libbpf_probe_bpf_helper(prog_type, func_id, dummy_ptr);

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

    LLVMFuzzerTestOneInput_75(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
