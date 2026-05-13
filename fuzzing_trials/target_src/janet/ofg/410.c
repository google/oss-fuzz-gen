#include <stdint.h>
#include <janet.h>

// Define a sample C function to be wrapped
static Janet my_c_function(int32_t argc, Janet *argv) {
    // Simple function that returns nil
    return janet_wrap_nil();
}

int LLVMFuzzerTestOneInput_410(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to be used meaningfully
    if (size < sizeof(JanetCFunction)) {
        return 0;
    }

    // Cast the data to a JanetCFunction pointer
    JanetCFunction func = (JanetCFunction)my_c_function;

    // Call the function-under-test
    Janet result = janet_wrap_cfunction(func);

    // Perform some basic checks or operations on the result if needed
    // (For the purpose of fuzzing, we just ensure the function is called)

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

    LLVMFuzzerTestOneInput_410(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
