#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_203(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to create a Janet object
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Create a Janet object from the input data
    Janet janet_obj = janet_wrap_number((double)data[0]);

    // Call the function-under-test
    JanetTuple result = janet_unwrap_tuple(janet_obj);

    // Use the result in some way to avoid compiler optimizations
    // (In a real fuzzing scenario, the result would be analyzed for correctness)
    if (result != NULL) {
        // Do something with the result, like printing its length
        size_t len = janet_tuple_length(result);
        (void)len; // Suppress unused variable warning
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

    LLVMFuzzerTestOneInput_203(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
