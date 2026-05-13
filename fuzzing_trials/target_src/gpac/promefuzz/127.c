// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open_progressive at isom_read.c:503:8 in isomedia.h
// gf_isom_get_creation_time at isom_read.c:994:8 in isomedia.h
// gf_isom_open_segment at isom_read.c:3557:8 in isomedia.h
// gf_isom_get_current_top_box_offset at isom_read.c:3173:8 in isomedia.h
// gf_isom_refresh_fragmented at isom_read.c:3088:8 in isomedia.h
// gf_isom_reset_data_offset at isom_read.c:3151:8 in isomedia.h
// gf_isom_open_progressive at isom_read.c:503:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile *create_dummy_isofile() {
    GF_ISOFile *isom_file = NULL;
    u64 BytesMissing = 0;
    gf_isom_open_progressive("./dummy_file", 0, 0, 0, &isom_file, &BytesMissing);
    return isom_file;
}

int LLVMFuzzerTestOneInput_127(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    GF_ISOFile *isom_file = create_dummy_isofile();
    if (!isom_file) return 0;

    u64 creationTime = 0, modificationTime = 0, current_top_box_offset = 0, MissingBytes = 0;
    char fileName[] = "./dummy_file";

    // Fuzz gf_isom_get_creation_time
    gf_isom_get_creation_time(isom_file, &creationTime, &modificationTime);

    // Fuzz gf_isom_open_segment
    gf_isom_open_segment(isom_file, fileName, 0, Size, Data[0]);

    // Fuzz gf_isom_get_current_top_box_offset
    gf_isom_get_current_top_box_offset(isom_file, &current_top_box_offset);

    // Fuzz gf_isom_refresh_fragmented
    gf_isom_refresh_fragmented(isom_file, &MissingBytes, fileName);

    // Fuzz gf_isom_reset_data_offset
    gf_isom_reset_data_offset(isom_file, &current_top_box_offset);

    // Fuzz gf_isom_open_progressive
    GF_ISOFile *new_isom_file = NULL;
    gf_isom_open_progressive(fileName, 0, Size, 0, &new_isom_file, &MissingBytes);

    gf_isom_close(isom_file);
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

        LLVMFuzzerTestOneInput_127(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    