#include <stdint.h>
#include <stdlib.h>
#include <libdwarf.h>

int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function-under-test
    Dwarf_Attribute attr = (Dwarf_Attribute)data; // Cast data to Dwarf_Attribute
    Dwarf_Half form = (Dwarf_Half)(size > 0 ? data[0] : 0); // Use the first byte of data as Dwarf_Half
    Dwarf_Bool result;
    Dwarf_Error error = NULL;

    // Call the function-under-test
    int ret = dwarf_hasform(attr, form, &result, &error);

    // Handle the result and error if necessary (optional)
    if (error != NULL) {
        // Normally handle the error, but for fuzzing, we may just ignore it
        dwarf_dealloc(NULL, error, DW_DLA_ERROR);
    }

    return 0; // Return 0 to indicate the fuzzer should continue
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

    LLVMFuzzerTestOneInput_50(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
