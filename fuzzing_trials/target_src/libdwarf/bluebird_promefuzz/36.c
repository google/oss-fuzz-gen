#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "libdwarf.h"

#define DUMMY_FILE_PATH "./dummy_file"

// Helper function to write dummy data to a file
static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen(DUMMY_FILE_PATH, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

// Helper function to clean up Dwarf_Debug and Dwarf_Error
static void cleanup_dwarf(Dwarf_Debug dbg, Dwarf_Error error) {
    if (dbg) {
        dwarf_finish(dbg);
    }
    if (error) {
        dwarf_dealloc_error(NULL, error);
    }
}

// Fuzzing entry point
int LLVMFuzzerTestOneInput_36(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    write_dummy_file(Data, Size);

    char true_path_out_buffer[1024];
    unsigned int groupnumber = DW_GROUPNUMBER_ANY;
    unsigned int universalnumber = 0;
    Dwarf_Debug dbg = NULL;
    Dwarf_Error error = NULL;
    unsigned char path_source = 0;

    // Fuzz dwarf_init_path_a
    dwarf_init_path_a(DUMMY_FILE_PATH, true_path_out_buffer, sizeof(true_path_out_buffer),
                      groupnumber, universalnumber, NULL, NULL, &dbg, &error);
    cleanup_dwarf(dbg, error);

    // Fuzz dwarf_init_path_dl
    char *dl_path_array[] = {"/usr/lib/debug", "/usr/local/lib/debug"};
    unsigned int dl_path_array_size = 2;
    dbg = NULL;
    error = NULL;
    dwarf_init_path_dl(DUMMY_FILE_PATH, true_path_out_buffer, sizeof(true_path_out_buffer),
                       groupnumber, NULL, NULL, &dbg, dl_path_array, dl_path_array_size,
                       &path_source, &error);
    cleanup_dwarf(dbg, error);

    // Fuzz dwarf_init_path
    dbg = NULL;
    error = NULL;
    dwarf_init_path(DUMMY_FILE_PATH, true_path_out_buffer, sizeof(true_path_out_buffer),
                    groupnumber, NULL, NULL, &dbg, &error);
    cleanup_dwarf(dbg, error);

    // Fuzz dwarf_init_path_dl_a
    dbg = NULL;
    error = NULL;
    dwarf_init_path_dl_a(DUMMY_FILE_PATH, true_path_out_buffer, sizeof(true_path_out_buffer),
                         groupnumber, universalnumber, NULL, NULL, &dbg, dl_path_array,
                         dl_path_array_size, &path_source, &error);
    cleanup_dwarf(dbg, error);

    // Fuzz dwarf_object_detector_path_dSYM
    char outpath[1024];
    unsigned int ftype = 0, endian = 0, offsetsize = 0;
    Dwarf_Unsigned filesize = 0;
    int errcode = 0;
    dwarf_object_detector_path_dSYM(DUMMY_FILE_PATH, outpath, sizeof(outpath),
                                    dl_path_array, dl_path_array_size, &ftype, &endian,
                                    &offsetsize, &filesize, &path_source, &errcode);

    // Fuzz dwarf_srcfiles
    Dwarf_Die cu_die = NULL; // Normally obtained from other libdwarf calls
    char **srcfiles = NULL;
    Dwarf_Signed filecount = 0;
    error = NULL;
    int res = dwarf_srcfiles(cu_die, &srcfiles, &filecount, &error);
    if (res == DW_DLV_OK && srcfiles) {
        for (Dwarf_Signed i = 0; i < filecount; ++i) {
            dwarf_dealloc(NULL, srcfiles[i], DW_DLA_STRING);
        }
        dwarf_dealloc(NULL, srcfiles, DW_DLA_LIST);
    }
    if (error) {
        dwarf_dealloc_error(NULL, error);
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

    LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
