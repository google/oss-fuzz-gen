#include <stdint.h>
#include <stddef.h>
#include <janet.h>

extern JanetFile * janet_getjfile(const Janet *, int32_t);

int LLVMFuzzerTestOneInput_278(const uint8_t *data, size_t size) {
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Initialize Janet runtime
    janet_init();

    // Create a Janet array to hold the input data
    Janet *janet_data = (Janet *)data;

    // Use the first element of the input data as the Janet object
    Janet janet_obj = janet_data[0];

    // Use a fixed index for the second parameter
    int32_t index = 0;

    // Call the function-under-test
    JanetFile *result = janet_getjfile(&janet_obj, index);

    // Clean up Janet runtime
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

    LLVMFuzzerTestOneInput_278(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
