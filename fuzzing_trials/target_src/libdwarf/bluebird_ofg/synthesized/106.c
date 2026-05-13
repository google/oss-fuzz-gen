#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "libdwarf.h"
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_106(const uint8_t *data, size_t size) {
    // Check if the size is sufficient for a minimal valid input
    if (size < sizeof(Dwarf_Fde)) {
        return 0; // Not enough data to form a valid Dwarf_Fde
    }

    // Allocate memory for Dwarf_Fde and copy data into it
    Dwarf_Fde fde = malloc(size);
    if (!fde) {
        return 0; // Allocation failed
    }
    memcpy(fde, data, size);

    Dwarf_Cie cie;
    Dwarf_Error error;

    // Call the function-under-test
    int result = dwarf_get_cie_of_fde(fde, &cie, &error);

    // Use the result to prevent unused variable warnings
    if (result == DW_DLV_OK) {
        // Do something with cie if needed
    }

    // Free the allocated memory
    free(fde);

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_106(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
