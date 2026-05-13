#include <stdint.h>
#include <stddef.h>
#include <libdwarf.h>
#include <stdlib.h>

extern int dwarf_global_formref_b(Dwarf_Attribute attr, Dwarf_Off *return_offset, Dwarf_Bool *is_info, Dwarf_Error *error);

int LLVMFuzzerTestOneInput_62(const uint8_t *data, size_t size) {
    if (size < sizeof(Dwarf_Attribute)) {
        return 0;
    }

    Dwarf_Attribute attr = (Dwarf_Attribute)data;
    Dwarf_Off return_offset;
    Dwarf_Bool is_info;
    Dwarf_Error error;

    // Initialize the pointers to non-NULL values
    return_offset = 0;
    is_info = 0;
    error = NULL;

    // Call the function-under-test
    dwarf_global_formref_b(attr, &return_offset, &is_info, &error);

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

    LLVMFuzzerTestOneInput_62(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
