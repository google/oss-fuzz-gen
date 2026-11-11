#include <stdint.h>
#include <stddef.h>
#include <stdlib.h> // Include this for malloc and free
#include <libdwarf.h>

// Since Dwarf_Attribute and Dwarf_Error are typedefs to pointer types,
// we need to allocate memory for them and use the '->' operator for accessing members.

int LLVMFuzzerTestOneInput_90(const uint8_t *data, size_t size) {
    if (size < sizeof(uint64_t)) {
        return 0;
    }

    // Allocate memory for the Dwarf_Attribute parameter
    Dwarf_Attribute attr = 0; // Initialize to zero
    Dwarf_Error error = 0; // Initialize to zero

    // Initialize the Dwarf_Off parameter
    Dwarf_Off offset = 0;

    // Call the function-under-test
    int result = dwarf_global_formref(attr, &offset, &error);

    // Use the result, offset, and error for further checks if needed
    // For now, we just return 0 to indicate the fuzzing input was processed

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

    LLVMFuzzerTestOneInput_90(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
