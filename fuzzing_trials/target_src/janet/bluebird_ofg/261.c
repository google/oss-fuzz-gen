#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "janet.h"

// Remove the 'extern "C"' linkage specification for C++ since this is C code
int LLVMFuzzerTestOneInput_261(const uint8_t *data, size_t size) {
    // Initialize Janet runtime
    janet_init();

    // Create a Janet object from the input data
    Janet input;
    if (size >= sizeof(Janet)) {
        // Assuming the input data can be interpreted as a Janet object
        input = *((Janet *)data);
    } else {
        // If the input size is too small, create a default Janet object
        input = janet_wrap_nil();
    }

    // Call the function-under-test
    JanetString description = janet_description(input);

    // Use the description (for example, just check if it's not NULL)
    if (description) {
        // Do something with the description if needed
    }

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

    LLVMFuzzerTestOneInput_261(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
