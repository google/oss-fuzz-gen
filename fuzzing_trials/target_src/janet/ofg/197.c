#include <stdint.h>
#include <stddef.h>
#include <janet.h>

extern int janet_checkint(Janet);

int LLVMFuzzerTestOneInput_197(const uint8_t *data, size_t size) {
    if (size < sizeof(int32_t)) {
        return 0; // Not enough data to form an integer
    }

    // Use the first 4 bytes of data to form an integer
    int32_t int_value = *(const int32_t *)data;

    // Create a Janet object from the integer
    Janet janet_value = janet_wrap_integer(int_value);

    // Call the function-under-test
    int result = janet_checkint(janet_value);

    // The result can be used for further checks if needed
    (void)result; // Suppress unused variable warning

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

    LLVMFuzzerTestOneInput_197(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
