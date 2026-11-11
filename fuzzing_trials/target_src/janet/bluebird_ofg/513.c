#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

// Fuzzing harness for janet_is_int function
int LLVMFuzzerTestOneInput_513(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for a Janet value
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Create a Janet value from the input data
    Janet janetValue;
    memcpy(&janetValue, data, sizeof(Janet));

    // Call the function-under-test
    JanetIntType result = janet_is_int(janetValue);

    // Use the result to prevent compiler optimizations (if necessary)
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

    LLVMFuzzerTestOneInput_513(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
