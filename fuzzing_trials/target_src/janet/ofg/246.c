#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_246(const uint8_t *data, size_t size) {
    // Ensure that the size is at least 4 bytes to safely convert to int32_t
    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Interpret the first 4 bytes of data as an int32_t
    int32_t tuple_size = *(const int32_t *)data;

    // Ensure tuple_size is non-negative and within a reasonable limit to avoid invalid operations
    if (tuple_size < 0 || tuple_size > 1000) { // Limit size to prevent excessive memory allocation
        return 0;
    }

    // Call the function-under-test
    Janet *result = janet_tuple_begin(tuple_size);

    // Use the result in some way to avoid compiler optimizations removing the call
    if (result) {
        // Fill the tuple with some dummy data to ensure it's being used
        for (int32_t i = 0; i < tuple_size; i++) {
            result[i] = janet_wrap_integer(i);
        }
        janet_tuple_end(result);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_246(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
