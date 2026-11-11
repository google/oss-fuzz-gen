#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "dwarf.h"
#include "libdwarf.h"

int LLVMFuzzerTestOneInput_147(const uint8_t *data, size_t size) {
    Dwarf_Debug dbg1 = (Dwarf_Debug)data;  // Casting data to Dwarf_Debug type
    Dwarf_Debug dbg2 = (Dwarf_Debug)(data + size / 2);  // Use second half of data for dbg2
    Dwarf_Error error;

    // Ensure that dbg1 and dbg2 are not NULL by checking size
    if (size < 2 * sizeof(void*)) {
        return 0;
    }

    // Call the function under test
    int result = dwarf_set_tied_dbg(dbg1, dbg2, &error);

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

    LLVMFuzzerTestOneInput_147(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
