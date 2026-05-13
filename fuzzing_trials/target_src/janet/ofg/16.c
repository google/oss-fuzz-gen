#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    if (size < sizeof(int16_t)) {
        return 0;
    }

    // Initialize Janet
    janet_init();

    // Create a Janet value from the input data
    int16_t value;
    memcpy(&value, data, sizeof(int16_t));
    Janet janet_value = janet_wrap_integer((int32_t)value);

    // Call the function-under-test
    int result = janet_checkint16(janet_value);

    // Clean up Janet
    janet_deinit();

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

    LLVMFuzzerTestOneInput_16(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
