#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_69(const uint8_t *data, size_t size) {
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Initialize Janet VM
    janet_init();

    // Create a Janet array to hold the input data
    JanetArray *array = janet_array(size / sizeof(Janet));
    
    // Copy the input data into the Janet array
    for (size_t i = 0; i < size / sizeof(Janet); i++) {
        array->data[i] = ((Janet *)data)[i];
    }
    array->count = size / sizeof(Janet);

    // Ensure the index is within bounds
    int32_t index = size / sizeof(Janet) > 0 ? 0 : -1;

    // Call the function-under-test
    JanetFiber *fiber = janet_getfiber(array->data, index);

    // Clean up
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

    LLVMFuzzerTestOneInput_69(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
