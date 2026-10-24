#include <stdint.h>
#include <stddef.h>
#include <libdwarf.h>

int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for a Dwarf_Unsigned
    if (size < sizeof(Dwarf_Unsigned)) {
        return 0;
    }

    // Extract a Dwarf_Unsigned value from the input data
    Dwarf_Unsigned error_number = 0;
    for (size_t i = 0; i < sizeof(Dwarf_Unsigned) && i < size; ++i) {
        error_number = (error_number << 8) | data[i];
    }

    // Call the function-under-test
    char *error_message = dwarf_errmsg_by_number(error_number);

    // Optionally, you can perform further operations with error_message
    // For example, you could check if it is not NULL and perform some logging
    if (error_message != NULL) {
        // Log or use the error_message
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

    LLVMFuzzerTestOneInput_4(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
