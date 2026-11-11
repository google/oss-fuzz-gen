#include <sys/stat.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include "libdwarf.h"
#include "dwarf.h"

int LLVMFuzzerTestOneInput_125(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    Dwarf_Debug dbg = 0;
    Dwarf_Die die;
    Dwarf_Die sibling_die;
    Dwarf_Error error;
    Dwarf_Bool is_info = 1; // Assuming we are dealing with .debug_info section

    // Ensure that the data size is sufficient to initialize a Dwarf_Die
    if (size < sizeof(Dwarf_Die)) {
        return 0;
    }

    // Initialize the Dwarf_Die structure with data from the input
    die = *(Dwarf_Die *)data;

    // Call the function-under-test with the correct number of arguments
    int result = dwarf_siblingof_b(dbg, die, is_info, &sibling_die, &error);

    // Return 0 to indicate the fuzzer should continue
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

    LLVMFuzzerTestOneInput_125(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
