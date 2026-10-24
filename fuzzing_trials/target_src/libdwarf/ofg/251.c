#include <stddef.h>
#include <stdint.h>
#include <dwarf.h>
#include <libdwarf.h> // Include the necessary header for dwarf_get_AT_name

int LLVMFuzzerTestOneInput_251(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    unsigned int attribute = 0;
    const char *name = NULL;

    // Ensure there is enough data to read an unsigned int
    if (size >= sizeof(unsigned int)) {
        // Copy data to attribute
        attribute = *((unsigned int *)data);
    }

    // Call the function-under-test
    int result = dwarf_get_AT_name(attribute, &name);

    // Use the result and name to avoid compiler optimizations
    if (result == DW_DLV_OK && name != NULL) {
        // Do something with the name if needed
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

    LLVMFuzzerTestOneInput_251(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
