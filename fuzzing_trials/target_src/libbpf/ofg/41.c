#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libbpf/src/libbpf.h"

int LLVMFuzzerTestOneInput_41(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for creating a null-terminated string
    if (size < 1) return 0;

    // Create a dummy bpf_object
    struct bpf_object *bpf_obj = bpf_object__open_mem(data, size, NULL);
    if (!bpf_obj) return 0;

    // Create a null-terminated string from the input data
    char *map_name = (char *)malloc(size + 1);
    if (!map_name) {
        bpf_object__close(bpf_obj);
        return 0;
    }
    memcpy(map_name, data, size);
    map_name[size] = '\0';  // Null-terminate the string

    // Call the function-under-test
    int fd = bpf_object__find_map_fd_by_name(bpf_obj, map_name);

    // Clean up
    free(map_name);
    bpf_object__close(bpf_obj);

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

    LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
