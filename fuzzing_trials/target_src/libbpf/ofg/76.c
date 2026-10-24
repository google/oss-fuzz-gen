#include <stddef.h>
#include <stdint.h>
#include <linux/bpf.h> // Include the correct header for BPF types
#include "/src/libbpf/src/libbpf.h"

// Remove manual enumeration definitions since they are already defined in the included headers

extern int libbpf_probe_bpf_helper(enum bpf_prog_type prog_type, enum bpf_func_id func_id, const void *opts);

// Remove the 'extern "C"' linkage specification as it is not valid in C code
int LLVMFuzzerTestOneInput_76(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract enums and a pointer
    if (size < sizeof(enum bpf_prog_type) + sizeof(enum bpf_func_id) + sizeof(void *)) {
        return 0;
    }

    // Extract enums and pointer from data
    enum bpf_prog_type prog_type = (enum bpf_prog_type)data[0];
    enum bpf_func_id func_id = (enum bpf_func_id)data[1];
    const void *opts = (const void *)(data + 2);

    // Call the function-under-test
    libbpf_probe_bpf_helper(prog_type, func_id, opts);

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

    LLVMFuzzerTestOneInput_76(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
