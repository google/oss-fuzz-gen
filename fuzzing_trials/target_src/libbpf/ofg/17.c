#include <stddef.h>
#include <stdint.h>
#include "/src/libbpf/src/libbpf.h" // Correctly include the libbpf header

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    // Declare and initialize the bpf_object_open_opts structure
    struct bpf_object_open_opts open_opts = {
        .sz = sizeof(struct bpf_object_open_opts),
    };

    // Initialize the fields of the structure with non-null values
    struct bpf_object *obj = bpf_object__open_mem(data, size, &open_opts);

    if (!obj) {
        return 0; // If object creation fails, return 0
    }

    // Call the function-under-test
    int result = bpf_object__load(obj);

    // Clean up
    bpf_object__close(obj);

    // Return 0 to indicate successful execution of the fuzzer
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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
