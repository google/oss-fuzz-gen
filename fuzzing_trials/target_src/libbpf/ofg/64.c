#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "/src/libbpf/src/libbpf.h"

int LLVMFuzzerTestOneInput_64(const uint8_t *data, size_t size) {
    struct bpf_object *obj = NULL;
    struct btf *btf_result;

    // Initialize a bpf_object from the input data
    // For the purpose of fuzzing, we assume that the data represents an ELF file
    // containing BPF bytecode. In practice, you would need to ensure that the input
    // is a valid BPF object file.
    obj = bpf_object__open_mem(data, size, NULL);
    if (obj == NULL) {
        return 0;
    }

    // Call the function-under-test
    btf_result = bpf_object__btf(obj);

    // Cleanup
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

    LLVMFuzzerTestOneInput_64(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
