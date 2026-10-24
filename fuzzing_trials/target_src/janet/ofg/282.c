#include <stdint.h>
#include <stddef.h>
#include <janet.h>
#include <limits.h>

// Function to be used by the fuzzer
int LLVMFuzzerTestOneInput_282(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract an int32_t value
    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Extract an int32_t value from the input data
    int32_t count = *((int32_t *)data);

    // Ensure count is non-negative and within a reasonable range
    if (count < 0 || count > INT_MAX / sizeof(JanetKV)) {
        return 0;
    }

    // Call the function-under-test
    JanetKV *result = janet_struct_begin(count);

    // Normally, you would do something with 'result' here, but since this is a fuzz test,
    // we are primarily interested in whether the function can handle the input without crashing.

    // Use the result to maximize fuzzing effectiveness
    if (result) {
        // Do something with result to ensure it is not optimized away
        janet_struct_end(result);
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

    LLVMFuzzerTestOneInput_282(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
