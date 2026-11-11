// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_get_creation_time at isom_read.c:994:8 in isomedia.h
// gf_isom_open_segment at isom_read.c:3557:8 in isomedia.h
// gf_isom_get_current_top_box_offset at isom_read.c:3173:8 in isomedia.h
// gf_isom_refresh_fragmented at isom_read.c:3088:8 in isomedia.h
// gf_isom_reset_data_offset at isom_read.c:3151:8 in isomedia.h
// gf_isom_open_progressive at isom_read.c:503:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *f = fopen("./dummy_file", "wb");
    if (f) {
        fwrite(Data, 1, Size, f);
        fclose(f);
    }
}

int LLVMFuzzerTestOneInput_118(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u64) * 2) {
        return 0; // Not enough data to proceed
    }

    GF_ISOFile *isom_file = NULL;
    u64 *creationTime = (u64 *)malloc(sizeof(u64));
    u64 *modificationTime = (u64 *)malloc(sizeof(u64));
    u64 *current_top_box_offset = (u64 *)malloc(sizeof(u64));
    u64 *MissingBytes = (u64 *)malloc(sizeof(u64));
    u64 *top_box_start = (u64 *)malloc(sizeof(u64));
    GF_ISOFile **isom_file_ptr = (GF_ISOFile **)malloc(sizeof(GF_ISOFile *));
    *isom_file_ptr = NULL;
    u64 start_range = 0;
    u64 end_range = 0;
    GF_ISOSegOpenMode flags = 0;
    Bool enable_frag_templates = 0;

    if (!creationTime || !modificationTime || !current_top_box_offset || !MissingBytes || !top_box_start || !isom_file_ptr) {
        goto cleanup;
    }

    // Write data to a dummy file
    write_dummy_file(Data, Size);

    // Test gf_isom_get_creation_time
    gf_isom_get_creation_time(isom_file, creationTime, modificationTime);

    // Test gf_isom_open_segment
    gf_isom_open_segment(isom_file, "./dummy_file", start_range, end_range, flags);

    // Test gf_isom_get_current_top_box_offset
    gf_isom_get_current_top_box_offset(isom_file, current_top_box_offset);

    // Test gf_isom_refresh_fragmented
    gf_isom_refresh_fragmented(isom_file, MissingBytes, "./dummy_file");

    // Test gf_isom_reset_data_offset
    gf_isom_reset_data_offset(isom_file, top_box_start);

    // Test gf_isom_open_progressive
    gf_isom_open_progressive("./dummy_file", start_range, end_range, enable_frag_templates, isom_file_ptr, MissingBytes);

cleanup:
    free(creationTime);
    free(modificationTime);
    free(current_top_box_offset);
    free(MissingBytes);
    free(top_box_start);
    free(isom_file_ptr);

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

        LLVMFuzzerTestOneInput_118(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    