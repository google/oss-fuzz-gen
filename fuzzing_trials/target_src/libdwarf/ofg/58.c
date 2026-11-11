#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <libdwarf.h>

int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size) {
    Dwarf_Debug dbg = (Dwarf_Debug)data;  // Type casting data to Dwarf_Debug
    Dwarf_Global *globals = NULL;
    Dwarf_Signed count = 0;
    Dwarf_Error error = NULL;
    int result;

    // Call the function-under-test
    result = dwarf_get_globals(dbg, &globals, &count, &error);

    // Clean up if necessary
    if (globals != NULL) {
        dwarf_globals_dealloc(dbg, globals, count);
    }

    if (error != NULL) {
        dwarf_dealloc(dbg, error, DW_DLA_ERROR);
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

    LLVMFuzzerTestOneInput_58(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
