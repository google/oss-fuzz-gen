#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "libdwarf.h"

static unsigned int fuzz_dwarf_basic_crc32(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;
    unsigned int crc = 0;
    return dwarf_basic_crc32(Data, Size, crc);
}

static int fuzz_dwarf_crc32(Dwarf_Debug dw_dbg, Dwarf_Error *dw_error) {
    unsigned char crcbuf[4];
    return dwarf_crc32(dw_dbg, crcbuf, dw_error);
}

static int fuzz_dwarf_gnu_debuglink(Dwarf_Debug dw_dbg, Dwarf_Error *dw_error) {
    char *debuglink_path = NULL;
    unsigned char *crc = NULL;
    char *fullpath = NULL;
    unsigned int path_length = 0;
    unsigned int buildid_type = 0;
    char *owner_name = NULL;
    unsigned char *buildid = NULL;
    unsigned int buildid_length = 0;
    char **paths = NULL;
    unsigned int paths_length = 0;

    int result = dwarf_gnu_debuglink(dw_dbg, &debuglink_path, &crc, &fullpath,
                                     &path_length, &buildid_type, &owner_name,
                                     &buildid, &buildid_length, &paths,
                                     &paths_length, dw_error);

    if (fullpath) free(fullpath);
    if (paths) free(paths);

    return result;
}

static int fuzz_dwarf_init_path_dl(const char *path, Dwarf_Debug *dw_dbg, Dwarf_Error *dw_error) {
    unsigned char path_source;
    return dwarf_init_path_dl(path, NULL, 0, DW_GROUPNUMBER_ANY, NULL, NULL, dw_dbg, NULL, 0, &path_source, dw_error);
}

static int fuzz_dwarf_get_frame_section_name(Dwarf_Debug dw_dbg, Dwarf_Error *dw_error) {
    const char *section_name;
    return dwarf_get_frame_section_name(dw_dbg, &section_name, dw_error);
}

static int fuzz_dwarf_suppress_debuglink_crc(int suppress) {
    return dwarf_suppress_debuglink_crc(suppress);
}

int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Fuzz dwarf_basic_crc32
    fuzz_dwarf_basic_crc32(Data, Size);

    // Prepare a dummy Dwarf_Debug object
    Dwarf_Debug dw_dbg = NULL;
    Dwarf_Error dw_error = NULL;

    // Fuzz dwarf_crc32
    fuzz_dwarf_crc32(dw_dbg, &dw_error);

    // Fuzz dwarf_gnu_debuglink
    fuzz_dwarf_gnu_debuglink(dw_dbg, &dw_error);

    // Fuzz dwarf_init_path_dl
    fuzz_dwarf_init_path_dl("./dummy_file", &dw_dbg, &dw_error);

    // Fuzz dwarf_get_frame_section_name
    fuzz_dwarf_get_frame_section_name(dw_dbg, &dw_error);

    // Fuzz dwarf_suppress_debuglink_crc
    fuzz_dwarf_suppress_debuglink_crc(1);
    fuzz_dwarf_suppress_debuglink_crc(0);

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

    LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
