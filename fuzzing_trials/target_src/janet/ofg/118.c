#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_118(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to extract a uint64_t
    if (size < sizeof(uint64_t)) {
        return 0;
    }

    // Use the first part of the data as a pointer
    const void *ptr = (const void *)(data);

    // Use the next part of the data as a uint64_t
    uint64_t u64_value;
    // Copy the data into the uint64_t variable
    memcpy(&u64_value, data, sizeof(uint64_t));

    // Call the function-under-test
    Janet result = janet_nanbox_from_cpointer(ptr, u64_value);

    // Use the result in some way to avoid compiler optimizations removing the call
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_118(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
