#include <stdint.h>
#include <stdlib.h>
#include <libdwarf.h>

int LLVMFuzzerTestOneInput_19(const uint8_t *data, size_t size) {
    // Initialize Dwarf_Fde, Dwarf_Cie, and Dwarf_Error
    Dwarf_Fde fde;
    Dwarf_Cie cie = NULL;
    Dwarf_Error error = NULL;

    // Check if the size is sufficient to initialize a Dwarf_Fde
    if (size < sizeof(Dwarf_Fde)) {
        return 0; // Not enough data to proceed
    }

    // Cast data to Dwarf_Fde for fuzzing
    fde = (Dwarf_Fde)data;

    // Call the function-under-test
    int result = dwarf_get_cie_of_fde(fde, &cie, &error);

    // Perform any additional checks or operations here if needed

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

    LLVMFuzzerTestOneInput_19(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
