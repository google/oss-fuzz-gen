#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_215(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient for our needs
    if (size < sizeof(Janet) * 3 + sizeof(int32_t) * 2) {
        return 0;
    }

    // Initialize Janet VM
    janet_init();

    // Prepare Janet array
    Janet array[3];
    for (int i = 0; i < 3; i++) {
        array[i] = janet_wrap_integer((int32_t)data[i]);
    }

    // Extract int32_t values from the data
    int32_t n = (int32_t)data[3];
    int32_t m = (int32_t)data[4];

    // Prepare a default value
    Janet default_value = janet_wrap_integer((int32_t)data[5]);

    // Call the function-under-test
    JanetTuple result = janet_opttuple(array, n, m, &default_value);

    // Clean up Janet VM
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

    LLVMFuzzerTestOneInput_215(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
