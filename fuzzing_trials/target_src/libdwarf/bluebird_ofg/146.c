#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "libdwarf.h"
#include "dwarf.h"  // Include the necessary header for Dwarf_Debug and related types

int LLVMFuzzerTestOneInput_146(const uint8_t *data, size_t size) {
    Dwarf_Debug dbg = (Dwarf_Debug)data;  // Casting data to Dwarf_Debug for fuzzing
    Dwarf_Debug tied_dbg;
    Dwarf_Error error;

    // Ensure the data is not NULL and size is sufficient
    if (data == NULL || size < sizeof(Dwarf_Debug)) {
        return 0;
    }

    // Call the function-under-test
    int result = dwarf_get_tied_dbg(dbg, &tied_dbg, &error);

    // Optional: You can check the result or error for further validation
    // if (result != DW_DLV_OK) {
    //     // Handle error or log it
    // }

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

    LLVMFuzzerTestOneInput_146(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
