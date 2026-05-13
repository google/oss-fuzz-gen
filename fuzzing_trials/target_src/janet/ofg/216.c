#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include for memcpy
#include <janet.h>  // Assuming Janet library is available

// Function-under-test
int janet_checkuint64(Janet);

// Fuzzing harness
int LLVMFuzzerTestOneInput_216(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for a Janet value
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Create a Janet value from the input data
    Janet janet_value;
    memcpy(&janet_value, data, sizeof(Janet));

    // Call the function-under-test
    int result = janet_checkuint64(janet_value);

    // Use the result to avoid compiler optimizations
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

    LLVMFuzzerTestOneInput_216(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
