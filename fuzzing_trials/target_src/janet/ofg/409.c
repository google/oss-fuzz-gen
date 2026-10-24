#include <janet.h>
#include <string.h> // Include string.h for memcpy

// Define a simple JanetCFunction for testing purposes
static Janet my_cfunction(int32_t argc, Janet *argv) {
    (void)argc; // Suppress unused parameter warning
    (void)argv; // Suppress unused parameter warning
    return janet_wrap_nil();
}

int LLVMFuzzerTestOneInput_409(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a JanetCFunction
    if (size < sizeof(JanetCFunction)) {
        return 0;
    }

    // Use the predefined my_cfunction for fuzzing
    JanetCFunction cfunc = my_cfunction;

    // Call the function-under-test
    Janet result = janet_wrap_cfunction(cfunc);

    // Use the result in some way to avoid compiler optimizations removing the call
    // Here we just check if it's a function type
    if (janet_checktype(result, JANET_FUNCTION)) {
        // Do something if it's a function, though this is just a placeholder
    }

    // Utilize the input data in some way
    // For example, copy the data to a local buffer and use it in a meaningful way
    uint8_t buffer[256];
    size_t copy_size = size < sizeof(buffer) ? size : sizeof(buffer);
    memcpy(buffer, data, copy_size);

    // Additional operations can be performed on the buffer if needed

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

    LLVMFuzzerTestOneInput_409(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
