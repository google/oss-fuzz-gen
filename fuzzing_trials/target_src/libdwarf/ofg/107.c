#include <stdint.h>
#include <stdlib.h>
#include <libdwarf.h> // Include the necessary header for Dwarf_Unsigned

extern int dwarf_decode_leb128(char *, Dwarf_Unsigned *, Dwarf_Unsigned *, char *);

int LLVMFuzzerTestOneInput_107(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient for the function call
    if (size < 4) {
        return 0;
    }

    // Allocate memory for the parameters
    char *leb128_data = (char *)malloc(size);
    Dwarf_Unsigned decoded_value = 0;
    Dwarf_Unsigned length = 0;
    char *error = (char *)malloc(256); // Allocate some space for error messages

    // Copy the input data to leb128_data
    for (size_t i = 0; i < size; i++) {
        leb128_data[i] = (char)data[i];
    }

    // Call the function-under-test
    dwarf_decode_leb128(leb128_data, &decoded_value, &length, error);

    // Free allocated memory
    free(leb128_data);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_107(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
