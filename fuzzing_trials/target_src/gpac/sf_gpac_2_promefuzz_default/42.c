// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open_progressive_ex at isom_read.c:435:8 in isomedia.h
// gf_isom_reset_data_offset at isom_read.c:3151:8 in isomedia.h
// gf_isom_get_media_data_size at isom_read.c:4131:5 in isomedia.h
// gf_isom_get_fragmented_duration at isom_read.c:5409:5 in isomedia.h
// gf_isom_get_duration at isom_read.c:971:5 in isomedia.h
// gf_isom_get_first_mdat_start at isom_read.c:4163:5 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u64) + sizeof(u32)) return 0;

    GF_ISOFile *isom_file = NULL;
    u64 top_box_start = 0;
    u64 *top_box_start_ptr = NULL;
    u32 trackNumber = 0;
    u64 start_range = 0, end_range = 0;
    Bool enable_frag_templates = 0;
    u64 BytesMissing = 0;
    u32 topBoxType = 0;
    GF_Err err;

    // Write dummy file
    write_dummy_file(Data, Size);

    // Test gf_isom_open_progressive_ex
    err = gf_isom_open_progressive_ex("./dummy_file", start_range, end_range, enable_frag_templates, &isom_file, &BytesMissing, &topBoxType);
    if (err != 0 || !isom_file) {
        // Handle error if needed
        return 0;
    }

    // Test gf_isom_reset_data_offset
    err = gf_isom_reset_data_offset(isom_file, top_box_start_ptr);
    if (err != 0) {
        // Handle error if needed
    }

    // Test gf_isom_get_media_data_size
    u64 media_data_size = gf_isom_get_media_data_size(isom_file, trackNumber);

    // Test gf_isom_get_fragmented_duration
    u64 fragmented_duration = gf_isom_get_fragmented_duration(isom_file);

    // Test gf_isom_get_duration
    u64 duration = gf_isom_get_duration(isom_file);

    // Test gf_isom_get_first_mdat_start
    u64 first_mdat_start = gf_isom_get_first_mdat_start(isom_file);

    // Clean up if necessary
    if (isom_file) {
        // Assume some cleanup function exists, e.g., gf_isom_close_file(isom_file);
        // free(isom_file); // Uncomment if there's no specific cleanup function
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

        LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    