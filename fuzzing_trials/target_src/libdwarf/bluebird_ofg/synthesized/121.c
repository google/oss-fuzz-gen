#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "libdwarf.h"
#include "dwarf.h" // Include dwarf.h to ensure all types are defined

int LLVMFuzzerTestOneInput_121(const uint8_t *data, size_t size) {
    if (size < sizeof(Dwarf_Line_Context)) {
        return 0;
    }

    // Initialize variables
    Dwarf_Line_Context context = (Dwarf_Line_Context)data;
    Dwarf_Line *linebuf1 = NULL;
    Dwarf_Signed linecount1 = 0;
    Dwarf_Line *linebuf2 = NULL;
    Dwarf_Signed linecount2 = 0;
    Dwarf_Error error = NULL;

    // Call the function under test
    int result = dwarf_srclines_two_level_from_linecontext(
        context, &linebuf1, &linecount1, &linebuf2, &linecount2, &error);

    // Clean up and return
    if (linebuf1) {
        free(linebuf1);
    }
    if (linebuf2) {
        free(linebuf2);
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_121(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
