#include <stdint.h>
#include <string.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Initialize a Janet object using the input data
    Janet janetValue;
    memcpy(&janetValue, data, sizeof(Janet));

    // Call the function-under-test
    JanetCFunction result = janet_unwrap_cfunction(janetValue);

    // Use the result in some way to prevent compiler optimizations from removing the call
    if (result != NULL) {
        // For example, you could call the function with some dummy arguments
        Janet args[1];
        result(0, args);
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

    LLVMFuzzerTestOneInput_28(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
