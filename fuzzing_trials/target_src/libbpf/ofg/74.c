#include <stdint.h>
#include <stddef.h>
#include "/src/libbpf/src/libbpf.h"

int LLVMFuzzerTestOneInput_74(const uint8_t *data, size_t size) {
    // Declare and initialize a variable of type enum bpf_attach_type
    enum bpf_attach_type attach_type;

    // Ensure the size is sufficient to read an enum value
    if (size < sizeof(enum bpf_attach_type)) {
        return 0;
    }

    // Copy data into the attach_type variable
    attach_type = *(enum bpf_attach_type *)data;

    // Call the function-under-test
    const char *result = libbpf_bpf_attach_type_str(attach_type);

    // Use the result to avoid any compiler optimizations removing the call
    if (result) {
        // Do something trivial with the result
        (void)result[0];
    }

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

    LLVMFuzzerTestOneInput_74(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
