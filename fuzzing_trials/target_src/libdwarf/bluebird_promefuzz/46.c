#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "libdwarf.h"

// Dummy methods to satisfy the interface requirements
static int dummy_get_section_count(void *obj) { return 0; }
static int dummy_get_section_info(void *obj, Dwarf_Half section_index, Dwarf_Obj_Access_Section_a *return_section, int *error) { return DW_DLV_NO_ENTRY; }
static int dummy_load_section(void *obj, Dwarf_Half section_index, Dwarf_Small **return_data, int *error) { return DW_DLV_NO_ENTRY; }
static Dwarf_Unsigned dummy_get_filesize(void *obj) { return 0; }
static Dwarf_Small dummy_get_length_size(void *obj) { return 4; }
static Dwarf_Small dummy_get_pointer_size(void *obj) { return 8; }
static Dwarf_Small dummy_get_byte_order(void *obj) { return 0; } // Added to fix the error

static Dwarf_Obj_Access_Interface_a* create_dummy_obj_access_interface() {
    Dwarf_Obj_Access_Interface_a *interface = malloc(sizeof(Dwarf_Obj_Access_Interface_a));
    if (!interface) return NULL;

    Dwarf_Obj_Access_Methods_a *methods = malloc(sizeof(Dwarf_Obj_Access_Methods_a));
    if (!methods) {
        free(interface);
        return NULL;
    }

    methods->om_get_section_count = dummy_get_section_count;
    methods->om_get_section_info = dummy_get_section_info;
    methods->om_load_section = dummy_load_section;
    methods->om_get_filesize = dummy_get_filesize;
    methods->om_get_length_size = dummy_get_length_size;
    methods->om_get_pointer_size = dummy_get_pointer_size;
    methods->om_get_byte_order = dummy_get_byte_order; // Added to fix the error

    interface->ai_object = NULL;
    interface->ai_methods = methods;
    return interface;
}

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_46(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare environment
    write_dummy_file(Data, Size);
    
    // Fuzz dwarf_set_stringcheck
    int check_val = Data[0] % 2;
    int prev_check_state = dwarf_set_stringcheck(check_val);

    // Fuzz dwarf_set_reloc_application
    int reloc_val = Data[0] % 2;
    int prev_reloc_state = dwarf_set_reloc_application(reloc_val);

    // Fuzz dwarf_library_allow_dup_attr
    int dup_attr_val = Data[0] % 2;
    int prev_dup_attr_state = dwarf_library_allow_dup_attr(dup_attr_val);

    // Fuzz dwarf_set_de_alloc_flag
    int de_alloc_val = Data[0] % 2;
    int prev_de_alloc_state = dwarf_set_de_alloc_flag(de_alloc_val);

    // Fuzz dwarf_object_init_b
    Dwarf_Obj_Access_Interface_a* obj_interface = create_dummy_obj_access_interface();
    if (!obj_interface) return 0;

    Dwarf_Debug dbg;
    Dwarf_Error error;
    int res = dwarf_object_init_b(obj_interface, NULL, NULL, DW_GROUPNUMBER_ANY, &dbg, &error);
    if (res == DW_DLV_OK) {
        // Fuzz dwarf_get_die_section_name
        const char *sec_name;
        Dwarf_Bool is_info = Data[0] % 2;
        res = dwarf_get_die_section_name(dbg, is_info, &sec_name, &error);
    }
    
    // Cleanup
    if (res == DW_DLV_ERROR) {
        dwarf_dealloc_error(dbg, error);
    }
    free(obj_interface->ai_methods);
    free(obj_interface);
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

    LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
