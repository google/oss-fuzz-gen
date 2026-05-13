#include <stdint.h>
#include <stddef.h>
#include <string.h>  // Include for memcpy
#include <janet.h>

int LLVMFuzzerTestOneInput_202(const uint8_t *data, size_t size) {
    // Ensure that the input size is large enough to create a Janet object
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Create a Janet object from the input data
    Janet janetValue;
    memcpy(&janetValue, data, sizeof(Janet));

    // Call the function-under-test
    JanetTuple result = janet_unwrap_tuple(janetValue);

    // Use the result to avoid compiler optimizations that might skip the call
    if (result != NULL) {
        // Do something with result if needed
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

    LLVMFuzzerTestOneInput_202(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
