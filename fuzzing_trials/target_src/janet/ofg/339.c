#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include this for memcpy
#include <janet.h>

int LLVMFuzzerTestOneInput_339(const uint8_t *data, size_t size) {
    // Ensure that the size is at least the size of a Janet structure
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Create a Janet object from the input data
    Janet janet_value;
    memcpy(&janet_value, data, sizeof(Janet));

    // Call the function-under-test
    JanetString result = janet_unwrap_string(janet_value);

    // Use the result to prevent optimization removal
    if (result != NULL) {
        // Do something with the result, e.g., check its length
        janet_string_length(result);
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

    LLVMFuzzerTestOneInput_339(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
