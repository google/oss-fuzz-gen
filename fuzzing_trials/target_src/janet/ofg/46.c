#include <stdint.h>
#include <stddef.h>

// Assuming Janet is a type defined in the Janet library
typedef struct {
    // Dummy structure to represent Janet type
    uint64_t value;
} Janet;

// Dummy implementation of janet_nanbox_from_pointer_46 to allow compilation
Janet janet_nanbox_from_pointer_46(void *ptr, uint64_t extra) {
    Janet result;
    result.value = (uint64_t)ptr + extra;
    return result;
}

int LLVMFuzzerTestOneInput_46(const uint8_t *data, size_t size) {
    void *ptr = (void *)data; // Use data pointer as input
    uint64_t extra = 0;

    // Ensure size is large enough to extract a uint64_t
    if (size >= sizeof(uint64_t)) {
        // Extract uint64_t from data
        extra = *(const uint64_t *)data;
    }

    // Call the function-under-test
    Janet result = janet_nanbox_from_pointer_46(ptr, extra);

    // Use result in some way to avoid compiler optimizing the call away
    volatile uint64_t used = result.value;
    (void)used;

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_46(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
