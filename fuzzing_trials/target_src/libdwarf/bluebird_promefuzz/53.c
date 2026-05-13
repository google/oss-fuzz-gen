#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "fcntl.h"
#include <unistd.h>
#include "libdwarf.h"

#define DUMMY_ERROR_NO_ENTRY 999

static int dummy_get_section_info(void* obj, Dwarf_Unsigned section_index, Dwarf_Obj_Access_Section_a* return_section, int *error) {
    if (section_index >= 1) {
        *error = DUMMY_ERROR_NO_ENTRY;
        return DW_DLV_NO_ENTRY;
    }
    return_section->as_size = 1024;
    return_section->as_addr = 0;
    return_section->as_link = 0;
    return_section->as_entrysize = 0;
    return_section->as_name = ".dummy_section";
    return_section->as_type = 0;
    return DW_DLV_OK;
}

static Dwarf_Small dummy_get_byte_order(void* obj) {
    return 0;
}

static Dwarf_Small dummy_get_length_size(void* obj) {
    return 4;
}

static Dwarf_Small dummy_get_pointer_size(void* obj) {
    return 8;
}

static Dwarf_Unsigned dummy_get_filesize(void* obj) {
    return 1024;
}

static Dwarf_Unsigned dummy_get_section_count(void* obj) {
    return 1;
}

static int dummy_load_section(void* obj, Dwarf_Unsigned dw_section_index, Dwarf_Small **dw_return_data, int *dw_error) {
    if (dw_section_index >= 1) {
        *dw_error = DUMMY_ERROR_NO_ENTRY;
        return DW_DLV_NO_ENTRY;
    }
    *dw_return_data = (Dwarf_Small *)malloc(1024);
    if (!*dw_return_data) {
        *dw_error = DW_DLE_ALLOC_FAIL;
        return DW_DLV_ERROR;
    }
    memset(*dw_return_data, 0, 1024);
    return DW_DLV_OK;
}

static int dummy_relocate_a_section(void* obj, Dwarf_Unsigned section_index, Dwarf_Debug dbg, int *error) {
    return DW_DLV_OK;
}

static void dummy_finish(void * obj) {
    // Do nothing
}

static Dwarf_Obj_Access_Methods_a dummy_methods = {
    dummy_get_section_info,
    dummy_get_byte_order,
    dummy_get_length_size,
    dummy_get_pointer_size,
    dummy_get_filesize,
    dummy_get_section_count,
    dummy_load_section,
    dummy_relocate_a_section,
    NULL,
    dummy_finish
};

static void dummy_write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_53(const uint8_t *Data, size_t Size) {
    Dwarf_Obj_Access_Interface_a obj_interface;
    obj_interface.ai_object = NULL;
    obj_interface.ai_methods = &dummy_methods;

    Dwarf_Debug dbg = 0;
    Dwarf_Error error = 0;
    int res;

    // Fuzzing dwarf_object_init_b
    res = dwarf_object_init_b(&obj_interface, NULL, NULL, DW_GROUPNUMBER_ANY, &dbg, &error);
    if (res == DW_DLV_ERROR) {
        dwarf_dealloc_error(dbg, error);
    } else if (res == DW_DLV_OK && dbg) {
        // Fuzzing dwarf_machine_architecture_a
        Dwarf_Small ftype, obj_pointersize, obj_is_big_endian, path_source;
        Dwarf_Unsigned obj_machine, obj_type, obj_flags, ub_offset, ub_count, ub_index, comdat_groupnumber;
        res = dwarf_machine_architecture_a(dbg, &ftype, &obj_pointersize, &obj_is_big_endian, &obj_machine, &obj_type, &obj_flags, &path_source, &ub_offset, &ub_count, &ub_index, &comdat_groupnumber);

        // Fuzzing dwarf_get_real_section_name
        const char *actual_sec_name_out;
        Dwarf_Small marked_zcompressed, marked_zlib_compressed, marked_shf_compressed;
        Dwarf_Unsigned compressed_length, uncompressed_length;
        res = dwarf_get_real_section_name(dbg, ".debug_info", &actual_sec_name_out, &marked_zcompressed, &marked_zlib_compressed, &marked_shf_compressed, &compressed_length, &uncompressed_length, &error);
        if (res == DW_DLV_ERROR) {
            dwarf_dealloc_error(dbg, error);
        }
    }

    // Fuzzing dwarf_object_detector_path_b
    unsigned int ftype, endian, offsetsize;
    Dwarf_Unsigned filesize;
    unsigned char pathsource;
    int errcode;
    dummy_write_dummy_file(Data, Size);
    res = dwarf_object_detector_path_b("./dummy_file", NULL, 0, NULL, 0, &ftype, &endian, &offsetsize, &filesize, &pathsource, &errcode);

    // Fuzzing dwarf_object_detector_fd
    int fd = open("./dummy_file", O_RDONLY);
    if (fd != -1) {
        res = dwarf_object_detector_fd(fd, &ftype, &endian, &offsetsize, &filesize, &errcode);
        close(fd);
    }

    // Fuzzing dwarf_object_detector_path_dSYM
    res = dwarf_object_detector_path_dSYM("./dummy_file", NULL, 0, NULL, 0, &ftype, &endian, &offsetsize, &filesize, &pathsource, &errcode);

    if (dbg) {
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_53(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
