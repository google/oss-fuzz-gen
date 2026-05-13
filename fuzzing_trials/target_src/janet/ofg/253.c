#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <janet.h>

extern void * janet_getpointer(const Janet *array, int32_t index);

int LLVMFuzzerTestOneInput_253(const uint8_t *data, size_t size) {
    if (size < sizeof(Janet) + sizeof(int32_t)) {
        return 0;
    }

    // Initialize the Janet environment
    janet_init();

    // Initialize a Janet value from the input data
    Janet janet_value;
    memcpy(&janet_value, data, sizeof(Janet));

    // Use the remaining data as the index
    int32_t index = 0;
    if (size >= sizeof(Janet) + sizeof(int32_t)) {
        memcpy(&index, data + sizeof(Janet), sizeof(int32_t));
    }

    // Ensure the Janet value is valid before passing it to the function
    if (janet_checktype(janet_value, JANET_ARRAY)) {
        // Call the function-under-test
        void *result = janet_getpointer(&janet_value, index);
        (void)result; // Suppress unused variable warning
    }

    // Deinitialize the Janet environment
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

    LLVMFuzzerTestOneInput_253(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
