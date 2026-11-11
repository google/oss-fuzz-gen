#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
    Janet result;

    // Initialize the Janet environment
    janet_init();

    // Ensure the data is not empty
    if (size > 0) {
        // Create a Janet string from the input data
        JanetString jstr = janet_string(data, size);

        // Call the function-under-test
        result = janet_wrap_string(jstr);
    }

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

    LLVMFuzzerTestOneInput_24(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
