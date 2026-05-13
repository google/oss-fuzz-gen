#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "libbpf.h"

int LLVMFuzzerTestOneInput_71(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract a bpf_link_type value
    if (size < sizeof(enum bpf_link_type)) {
        return 0;
    }

    // Extract the enum value from the input data
    enum bpf_link_type link_type = *(const enum bpf_link_type *)data;

    // Call the function-under-test
    const char *result = libbpf_bpf_link_type_str(link_type);

    // Use the result in some way to prevent it from being optimized away
    if (result) {
        // Simple operation to use the result
        volatile size_t length = 0;
        while (result[length] != '\0') {
            length++;
        }
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

    LLVMFuzzerTestOneInput_71(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
