#include <stdint.h>
#include <stddef.h>
#include <janet.h>

extern JanetIntType janet_is_int(Janet);

int LLVMFuzzerTestOneInput_65(const uint8_t *data, size_t size) {
    Janet janet_value;

    if (size < sizeof(Janet)) {
        return 0;
    }

    // Initialize a Janet value from the input data
    janet_value = *(Janet *)data;

    // Call the function-under-test
    JanetIntType result = janet_is_int(janet_value);

    // Use the result in some way to avoid compiler optimizations removing the call
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

    LLVMFuzzerTestOneInput_65(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
