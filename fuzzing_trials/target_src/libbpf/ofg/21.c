#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libbpf/src/libbpf.h"
#include "/src/libbpf/src/bpf.h"  // Include additional header for full definitions

int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Convert the input data to a string for the program name
    size_t name_len = size < 255 ? size : 255; // Limit the length to 255
    char *prog_name = (char *)malloc(name_len + 1);
    if (prog_name == NULL) {
        return 0;
    }
    memcpy(prog_name, data, name_len);
    prog_name[name_len] = '\0';

    // Use libbpf API to create a bpf_object
    struct bpf_object *obj = bpf_object__open(prog_name);
    if (!obj) {
        free(prog_name);
        return 0;
    }

    // Call the function under test
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_name);

    // Clean up
    bpf_object__close(obj);  // Properly close the bpf_object
    free(prog_name);

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

    LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
