#include <stdint.h>
#include <stddef.h>
#include <janet.h>

extern JanetArray * janet_optarray(const Janet *argv, int32_t argc, int32_t n, int32_t def);

int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    if (size < sizeof(Janet)) {
        return 0; // Not enough data to form a Janet value
    }

    // Initialize Janet environment
    janet_init();

    // Prepare inputs for janet_optarray
    const Janet *argv = (const Janet *)data;
    int32_t argc = size / sizeof(Janet); // Number of Janet elements in data
    int32_t n = 0; // Index to check in argv
    int32_t def = 0; // Default value if index is out of bounds

    // Call the function-under-test
    JanetArray *result = janet_optarray(argv, argc, n, def);

    // Clean up Janet environment
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

    LLVMFuzzerTestOneInput_8(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
