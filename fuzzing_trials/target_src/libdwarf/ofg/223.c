#include <stdint.h>
#include <stddef.h>
#include <libdwarf.h>
#include <dwarf.h>

int LLVMFuzzerTestOneInput_223(const uint8_t *data, size_t size) {
    // Declare a Dwarf_Global variable
    Dwarf_Global global;

    // Initialize the global variable with data if possible
    if (size >= sizeof(Dwarf_Global)) {
        // Assuming data can be interpreted as a Dwarf_Global
        global = *(Dwarf_Global *)data;
    } else {
        // If not enough data to form a Dwarf_Global, return early
        return 0;
    }

    // Call the function-under-test
    Dwarf_Half result = dwarf_global_tag_number(global);

    // Use the result in some way to avoid compiler optimizations removing the call
    (void)result;

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

    LLVMFuzzerTestOneInput_223(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
