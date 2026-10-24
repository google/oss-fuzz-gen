#include <stdint.h>
#include <string.h>
#include <janet.h> // Ensure this header is available in your include path

int LLVMFuzzerTestOneInput_292(const uint8_t *data, size_t size) {
    // Ensure the Janet environment is initialized
    janet_init();

    if (size < sizeof(Janet)) {
        janet_deinit(); // Clean up the Janet environment
        return 0;
    }

    // Initialize a Janet variable from the input data
    Janet janet_value;
    memcpy(&janet_value, data, sizeof(Janet));

    // Call the function-under-test
    JanetType type = janet_type(janet_value);

    // Use the result to prevent the compiler from optimizing the call away
    (void)type;

    // Clean up the Janet environment
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

    LLVMFuzzerTestOneInput_292(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
