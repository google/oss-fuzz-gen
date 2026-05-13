#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_59(const uint8_t *data, size_t size) {
    // Ensure there's enough data to form a Janet structure
    if (size < sizeof(int64_t)) {
        return 0;
    }

    // Construct a Janet value from the input data
    int64_t input_value;
    memcpy(&input_value, data, sizeof(int64_t));
    Janet janet_value = janet_wrap_integer(input_value);

    // Call the function-under-test
    int64_t result = janet_unwrap_s64(janet_value);

    // Do something with the result to avoid compiler optimizing away the call
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

    LLVMFuzzerTestOneInput_59(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
