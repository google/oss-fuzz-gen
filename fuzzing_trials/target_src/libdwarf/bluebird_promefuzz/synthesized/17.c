#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "libdwarf.h"

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fputs("dummy content", file);
        fclose(file);
    }
}

static Dwarf_Debug create_dummy_debug() {
    return NULL; // As we cannot instantiate directly, return NULL
}

static Dwarf_Die create_dummy_die() {
    return NULL; // As we cannot instantiate directly, return NULL
}

static Dwarf_Macro_Context create_dummy_macro_context() {
    return NULL; // As we cannot instantiate directly, return NULL
}

int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Unsigned)) {
        return 0;
    }

    write_dummy_file();
    Dwarf_Debug dbg = create_dummy_debug();
    Dwarf_Die die = create_dummy_die();
    Dwarf_Macro_Context macro_context = create_dummy_macro_context();
    Dwarf_Error error = NULL;

    Dwarf_Unsigned op_number = *(Dwarf_Unsigned *)Data;
    Dwarf_Unsigned line_number = 0;
    Dwarf_Unsigned name_index = 0;
    const char *src_file_name = NULL;

    // Fuzz dwarf_get_macro_startend_file
    int res = dwarf_get_macro_startend_file(macro_context, op_number, &line_number, &name_index, &src_file_name, &error);
    if (res == DW_DLV_ERROR && error) {
        dwarf_dealloc_error(dbg, error);
    }

    // Fuzz dwarf_macro_context_total_length
    Dwarf_Unsigned total_length = 0;
    res = dwarf_macro_context_total_length(macro_context, &total_length, &error);
    if (res == DW_DLV_ERROR && error) {
        dwarf_dealloc_error(dbg, error);
    }

    // Fuzz dwarf_get_macro_context_by_offset
    Dwarf_Unsigned version_out = 0;
    Dwarf_Unsigned macro_ops_count_out = 0;
    Dwarf_Unsigned macro_ops_data_length = 0;
    res = dwarf_get_macro_context_by_offset(die, op_number, &version_out, &macro_context, &macro_ops_count_out, &macro_ops_data_length, &error);
    if (res == DW_DLV_ERROR && error) {
        dwarf_dealloc_error(dbg, error);
    }

    // Fuzz dwarf_get_macro_defundef
    Dwarf_Unsigned index = 0;
    Dwarf_Unsigned offset = 0;
    Dwarf_Half forms_count = 0;
    const char *macro_string = NULL;
    res = dwarf_get_macro_defundef(macro_context, op_number, &line_number, &index, &offset, &forms_count, &macro_string, &error);
    if (res == DW_DLV_ERROR && error) {
        dwarf_dealloc_error(dbg, error);
    }

    // Fuzz dwarf_get_macro_context
    Dwarf_Unsigned macro_unit_offset_out = 0;
    Dwarf_Unsigned macro_ops_data_length_out = 0;
    res = dwarf_get_macro_context(die, &version_out, &macro_context, &macro_unit_offset_out, &macro_ops_count_out, &macro_ops_data_length_out, &error);
    if (res == DW_DLV_ERROR && error) {
        dwarf_dealloc_error(dbg, error);
    }

    // Cleanup
    if (macro_context) {
        dwarf_dealloc_macro_context(macro_context);
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
