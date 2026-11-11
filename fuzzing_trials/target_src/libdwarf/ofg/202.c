#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include for strlen
#include <dwarf.h>   // Assuming DW_DLV_OK is defined here
#include <libdwarf.h> // This is a common header for libdwarf functions and definitions

extern int dwarf_get_ORD_name(unsigned int ord, const char **name);

int LLVMFuzzerTestOneInput_202(const uint8_t *data, size_t size) {
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    // Extract an unsigned int from the input data
    unsigned int ord = *(const unsigned int *)data;

    // Prepare a pointer for the name output
    const char *name = NULL;

    // Call the function-under-test
    int result = dwarf_get_ORD_name(ord, &name);

    // Use the result and name in some way to prevent compiler optimizations
    // from removing the call to dwarf_get_ORD_name.
    if (result == DW_DLV_OK && name != NULL) {
        volatile size_t name_length = strlen(name);
        (void)name_length;
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

    LLVMFuzzerTestOneInput_202(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
