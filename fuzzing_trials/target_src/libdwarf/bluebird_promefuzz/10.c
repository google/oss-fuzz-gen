#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "libdwarf.h"

// Dummy file path
#define DUMMY_FILE_PATH "./dummy_file"

// Dummy constants for fuzzing
#define DUMMY_DW_AT_NAME 0x3
#define DUMMY_DW_FORM_DATA4 0x6

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen(DUMMY_FILE_PATH, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size) {
    write_dummy_file(Data, Size);

    // Declare variables for the function calls
    Dwarf_Debug dbg = NULL;
    Dwarf_Attribute attr = NULL;
    Dwarf_Arange arange = NULL;
    Dwarf_Global global = NULL;
    Dwarf_Error error = NULL;

    // Fuzz dwarf_global_formref_b
    Dwarf_Off return_offset;
    Dwarf_Bool offset_is_info;
    dwarf_global_formref_b(attr, &return_offset, &offset_is_info, &error);

    // Fuzz dwarf_get_form_class
    dwarf_get_form_class(2, DUMMY_DW_AT_NAME, 4, DUMMY_DW_FORM_DATA4);

    // Fuzz dwarf_highpc_b
    Dwarf_Addr return_addr;
    Dwarf_Half return_form;
    enum Dwarf_Form_Class return_class;
    dwarf_highpc_b(NULL, &return_addr, &return_form, &return_class, &error);

    // Fuzz dwarf_next_cu_header_d
    Dwarf_Unsigned cu_header_length;
    Dwarf_Half version_stamp, address_size, length_size, extension_size, header_cu_type;
    Dwarf_Off abbrev_offset;
    Dwarf_Unsigned typeoffset, next_cu_header_offset;
    Dwarf_Sig8 type_signature;
    dwarf_next_cu_header_d(dbg, 1, &cu_header_length, &version_stamp, &abbrev_offset,
                           &address_size, &length_size, &extension_size, &type_signature,
                           &typeoffset, &next_cu_header_offset, &header_cu_type, &error);

    // Fuzz dwarf_global_tag_number
    dwarf_global_tag_number(global);

    // Fuzz dwarf_get_cu_die_offset
    Dwarf_Off cu_die_offset;
    dwarf_get_cu_die_offset(arange, &cu_die_offset, &error);

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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
