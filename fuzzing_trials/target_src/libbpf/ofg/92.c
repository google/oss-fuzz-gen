#include <stdint.h>
#include <stddef.h>
#include <stdio.h> // Include the standard I/O library for potential debugging
#include "/src/libbpf/src/libbpf.h"

int LLVMFuzzerTestOneInput_92(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to extract an integer value for the enumeration
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer value from the data, ensuring it fits within the enum range
    int map_type = *(const int *)data;

    // Call the function-under-test
    const char *result = libbpf_bpf_map_type_str((enum bpf_map_type)map_type);

    // Use the result in some way to prevent optimizations from removing the call
    if (result != NULL) {
        // For example, we can print it or perform some trivial operation
        // However, in fuzzing, we generally don't need to do anything with it
        // printf("Result: %s\n", result);
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

    LLVMFuzzerTestOneInput_92(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
