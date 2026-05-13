#include <stdint.h>
#include <stdlib.h>
#include <libdwarf.h>

// Dummy implementations of the methods to be used in the interface
int dummy_get_section_info(void* obj, Dwarf_Unsigned section_index, Dwarf_Obj_Access_Section_a* return_section, int* error) {
    return DW_DLV_OK;
}

Dwarf_Small dummy_get_byte_order(void* obj) {
    return 0;
}

Dwarf_Small dummy_get_length_size(void* obj) {
    return 8;
}

Dwarf_Small dummy_get_pointer_size(void* obj) {
    return 8;
}

Dwarf_Unsigned dummy_get_filesize(void* obj) {
    return 0;
}

Dwarf_Unsigned dummy_get_section_count(void* obj) {
    return 0;
}

int dummy_load_section(void* obj, Dwarf_Unsigned dw_section_index, Dwarf_Small** dw_return_data, int* dw_error) {
    return DW_DLV_OK;
}

int dummy_relocate_a_section(void* obj, Dwarf_Unsigned section_index, Dwarf_Debug dbg, int* error) {
    return DW_DLV_OK;
}

void dummy_finish(void* obj) {
    // Do nothing
}

int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    Dwarf_Obj_Access_Methods_a methods = {
        .om_get_section_info = dummy_get_section_info,
        .om_get_byte_order = dummy_get_byte_order,
        .om_get_length_size = dummy_get_length_size,
        .om_get_pointer_size = dummy_get_pointer_size,
        .om_get_filesize = dummy_get_filesize,
        .om_get_section_count = dummy_get_section_count,
        .om_load_section = dummy_load_section,
        .om_relocate_a_section = dummy_relocate_a_section,
        .om_load_section_a = NULL, // Not used
        .om_finish = dummy_finish
    };

    Dwarf_Obj_Access_Interface_a obj_access = {
        .ai_object = (void *)data,
        .ai_methods = &methods
    };

    Dwarf_Handler err_handler = NULL;
    Dwarf_Ptr err_arg = NULL;
    unsigned int access_flags = 0;
    Dwarf_Debug dbg = NULL;
    Dwarf_Error error = NULL;

    // Call the function under test
    dwarf_object_init_b(&obj_access, err_handler, err_arg, access_flags, &dbg, &error);

    // Cleanup if needed
    if (dbg != NULL) {
        dwarf_finish(dbg);
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

    LLVMFuzzerTestOneInput_42(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
