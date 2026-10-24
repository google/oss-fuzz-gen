#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_79(const uint8_t *data, size_t size) {
    // Initialize Janet
    janet_init();

    // Allocate a JanetKV structure
    JanetKV *kv = janet_struct_begin(1);  // Start with a small size for simplicity

    // Ensure we have enough data to create two Janet values
    if (size < 2 * sizeof(Janet)) {
        janet_deinit();
        return 0;
    }

    // Create two Janet values from the input data
    // For simplicity, let's assume the data can be interpreted as integers
    Janet key = janet_wrap_integer((int32_t)data[0]);
    Janet value = janet_wrap_integer((int32_t)data[1]);

    // Call the function-under-test
    janet_struct_put(kv, key, value);

    // Finish the struct
    JanetStruct my_struct = janet_struct_end(kv);

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

    LLVMFuzzerTestOneInput_79(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
