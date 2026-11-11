#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "/src/libbpf/src/libbpf.h"

// Define a mock structure for bpf_object as the actual structure is part of the libbpf library
struct bpf_object {
    int dummy; // Placeholder member
};

// Function signature to be fuzzed
int bpf_object__token_fd(const struct bpf_object *obj);

int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a bpf_object
    if (size < sizeof(struct bpf_object)) {
        return 0;
    }

    // Initialize a bpf_object using the provided data
    struct bpf_object obj;
    // Copy data into the bpf_object structure
    memcpy(&obj, data, sizeof(struct bpf_object));

    // Call the function-under-test
    int result = bpf_object__token_fd(&obj);

    // Use the result in some way to prevent compiler optimizations from removing the call
    (void)result;

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

    LLVMFuzzerTestOneInput_58(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
