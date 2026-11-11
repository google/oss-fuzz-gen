#include <stdint.h>
#include <stddef.h>
#include <libdwarf.h>

// Define the fuzzer test function
int LLVMFuzzerTestOneInput_112(const uint8_t *data, size_t size) {
    // Ensure size is large enough to create necessary structures
    if (size < sizeof(Dwarf_Fde) + sizeof(Dwarf_Unsigned)) {
        return 0;
    }

    // Initialize Dwarf_Fde and Dwarf_Error structures
    Dwarf_Fde fde1;
    Dwarf_Fde fde2;
    Dwarf_Error error;

    // Set up a Dwarf_Unsigned value from the input data
    Dwarf_Unsigned index = *(Dwarf_Unsigned *)data;

    // Call the function-under-test
    int result = dwarf_get_fde_n(&fde1, index, &fde2, &error);

    // Return 0 as the fuzzer test function should always return 0
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

    LLVMFuzzerTestOneInput_112(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
