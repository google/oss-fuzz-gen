#include <stdint.h>
#include <stddef.h>
#include <janet.h>

extern JanetKV * janet_struct_begin(int32_t);

int LLVMFuzzerTestOneInput_283(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    // Ensure there's enough data to extract an int32_t value
    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Extract an int32_t value from the input data
    int32_t capacity = *(int32_t *)data;

    // Call the function-under-test
    JanetKV *result = janet_struct_begin(capacity);

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

    LLVMFuzzerTestOneInput_283(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
