#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <janet.h>

// Initialize the Janet environment
static void initialize_janet_86() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

int LLVMFuzzerTestOneInput_86(const uint8_t *data, size_t size) {
    // Ensure there is enough data to create a Janet object and an index
    if (size < sizeof(Janet) + sizeof(int32_t)) {
        return 0;
    }

    // Initialize the Janet environment
    initialize_janet_86();

    // Initialize the Janet object from the input data
    Janet janet_obj;
    memcpy(&janet_obj, data, sizeof(Janet));

    // Extract the index from the remaining data
    int32_t index;
    memcpy(&index, data + sizeof(Janet), sizeof(int32_t));

    // Ensure the Janet object is a valid string
    if (!janet_checktype(janet_obj, JANET_STRING)) {
        return 0;
    }

    // Call the function-under-test with the address of janet_obj
    JanetString result = janet_getstring(&janet_obj, index);

    // Use the result in some way to avoid compiler optimizations ignoring the call
    if (result != NULL) {
        // Do something with result, e.g., print or log it
    }

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

    LLVMFuzzerTestOneInput_86(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
