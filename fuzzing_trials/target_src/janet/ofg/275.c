#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_275(const uint8_t *data, size_t size) {
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Initialize a Janet object from the input data
    Janet janet_obj;
    memcpy(&janet_obj, data, sizeof(Janet));

    // Ensure the index is within a reasonable range
    int32_t index = 0;
    if (size > sizeof(Janet)) {
        index = (int32_t)data[sizeof(Janet)]; // Use the next byte as the index
    }

    // Ensure the Janet object is properly initialized
    if (!janet_checktype(janet_obj, JANET_STRING)) {
        return 0;
    }

    // Call the function-under-test
    JanetByteView byte_view = janet_getbytes(&janet_obj, index);

    // Optionally, use byte_view in some way to prevent compiler optimizations
    if (byte_view.bytes != NULL) {
        // Do something with byte_view.bytes
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

    LLVMFuzzerTestOneInput_275(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
