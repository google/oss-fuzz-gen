#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "/src/libbpf/src/libbpf.h"

int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    char program_name[256];

    // Ensure the data size is sufficient for a null-terminated string
    if (size < 1 || size >= sizeof(program_name)) {
        return 0;
    }

    // Copy data into program_name and ensure null-termination
    memcpy(program_name, data, size);
    program_name[size] = '\0';

    // Initialize a dummy bpf_object for testing
    obj = bpf_object__open_mem(data, size, NULL);
    if (!obj) {
        return 0;
    }

    // Call the function-under-test
    prog = bpf_object__find_program_by_name(obj, program_name);

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

    LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
