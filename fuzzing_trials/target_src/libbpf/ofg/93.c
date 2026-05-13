#include <stdint.h>
#include <stddef.h>
#include "/src/libbpf/src/libbpf.h"

int LLVMFuzzerTestOneInput_93(const uint8_t *data, size_t size) {
    struct bpf_object *obj;
    int fd;

    // Initialize the BPF object from the input data
    obj = bpf_object__open_mem(data, size, NULL);
    if (!obj) {
        return 0; // If the object cannot be opened, exit early
    }

    // Load the BPF object
    if (bpf_object__load(obj) != 0) {
        bpf_object__close(obj);
        return 0; // If the object cannot be loaded, exit early
    }

    // Call the function-under-test
    fd = bpf_object__btf_fd(obj);

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

    LLVMFuzzerTestOneInput_93(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
