#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "libdwarf.h"

extern int dwarf_linecontext(Dwarf_Line, Dwarf_Unsigned *, Dwarf_Error *);

int LLVMFuzzerTestOneInput_112(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for the fuzzing
    if (size < sizeof(Dwarf_Line) + sizeof(Dwarf_Unsigned)) {
        return 0;
    }

    // Initialize the Dwarf_Line object from the input data
    Dwarf_Line line = (Dwarf_Line)data;

    // Allocate memory for Dwarf_Unsigned
    Dwarf_Unsigned *linecontext = (Dwarf_Unsigned *)malloc(sizeof(Dwarf_Unsigned));
    if (linecontext == NULL) {
        return 0;
    }

    // Allocate memory for Dwarf_Error
    Dwarf_Error *error = (Dwarf_Error *)malloc(sizeof(Dwarf_Error));
    if (error == NULL) {
        free(linecontext);
        return 0;
    }

    // Call the function-under-test
    int result = dwarf_linecontext(line, linecontext, error);

    // Clean up
    free(linecontext);
    free(error);

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

    LLVMFuzzerTestOneInput_112(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
