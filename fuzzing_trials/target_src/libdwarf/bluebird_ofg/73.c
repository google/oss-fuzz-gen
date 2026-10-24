#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "dwarf.h"
#include "libdwarf.h"

extern int dwarf_dnames_bucket(Dwarf_Dnames_Head, Dwarf_Unsigned, Dwarf_Unsigned *, Dwarf_Unsigned *, Dwarf_Error *);

int LLVMFuzzerTestOneInput_73(const uint8_t *data, size_t size) {
    // Check if the size is sufficient to create a valid Dwarf_Dnames_Head
    if (size < sizeof(Dwarf_Dnames_Head)) {
        return 0; // Not enough data to proceed
    }

    // Declare and initialize variables
    Dwarf_Dnames_Head dnames_head = (Dwarf_Dnames_Head)data; // Cast data to Dwarf_Dnames_Head
    Dwarf_Unsigned index = 0; // Initialize index to 0
    Dwarf_Unsigned result1 = 0; // Initialize result1 to 0
    Dwarf_Unsigned result2 = 0; // Initialize result2 to 0
    Dwarf_Error error = NULL; // Initialize error to NULL

    // Call the function-under-test
    int ret = dwarf_dnames_bucket(dnames_head, index, &result1, &result2, &error);

    // Return 0 to indicate successful execution
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

    LLVMFuzzerTestOneInput_73(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
