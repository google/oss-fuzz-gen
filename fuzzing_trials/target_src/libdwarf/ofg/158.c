#include <stdint.h>
#include <stddef.h>
#include <libdwarf.h>
#include <dwarf.h> // Include this header for Dwarf_Bool and related functions

int LLVMFuzzerTestOneInput_158(const uint8_t *data, size_t size) {
    // Ensure we have at least 4 bytes to read an int
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the input data
    int input_value = 0;
    for (size_t i = 0; i < sizeof(int); i++) {
        input_value |= ((int)data[i]) << (i * 8);
    }

    // Call the function-under-test
    Dwarf_Bool result = dwarf_addr_form_is_indexed(input_value);

    // Use the result in some way to avoid compiler optimizations
    if (result) {
        // Do something if result is true
    } else {
        // Do something if result is false
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

    LLVMFuzzerTestOneInput_158(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
