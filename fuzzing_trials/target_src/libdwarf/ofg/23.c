#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <libdwarf.h>

extern int dwarf_encode_leb128(Dwarf_Unsigned value, int *nbytes, char *space, int sp_size);

int LLVMFuzzerTestOneInput_23(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to extract necessary inputs
    if (size < sizeof(Dwarf_Unsigned) + sizeof(int)) {
        return 0;
    }

    // Extract a Dwarf_Unsigned value from the data
    Dwarf_Unsigned value = 0;
    for (size_t i = 0; i < sizeof(Dwarf_Unsigned) && i < size; ++i) {
        value = (value << 8) | data[i];
    }

    // Extract an integer for nbytes
    int nbytes = 0;
    for (size_t i = 0; i < sizeof(int) && i < size - sizeof(Dwarf_Unsigned); ++i) {
        nbytes = (nbytes << 8) | data[sizeof(Dwarf_Unsigned) + i];
    }

    // Allocate space for the encoded LEB128 output
    int sp_size = 10; // Arbitrary buffer size for LEB128 encoding
    char *space = (char *)malloc(sp_size);
    if (space == NULL) {
        return 0;
    }

    // Call the function-under-test
    dwarf_encode_leb128(value, &nbytes, space, sp_size);

    // Clean up
    free(space);

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

    LLVMFuzzerTestOneInput_23(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
