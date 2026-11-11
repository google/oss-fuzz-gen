#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// Function prototype for the function-under-test
int janet_checkint16(Janet value);

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    // Ensure there is enough data to construct a Janet value
    if (size < sizeof(int16_t)) {
        return 0;
    }

    // Create a Janet value from the input data
    int16_t intValue = *((int16_t *)data);
    Janet janetValue = janet_wrap_integer((int32_t)intValue);

    // Call the function-under-test
    int result = janet_checkint16(janetValue);

    // Use the result to prevent compiler optimizations from removing the call
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

    LLVMFuzzerTestOneInput_17(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
