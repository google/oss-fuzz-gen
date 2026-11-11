// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open_progressive_ex at isom_read.c:435:8 in isomedia.h
// gf_isom_reset_data_offset at isom_read.c:3151:8 in isomedia.h
// gf_isom_get_media_data_size at isom_read.c:4131:5 in isomedia.h
// gf_isom_get_fragmented_duration at isom_read.c:5409:5 in isomedia.h
// gf_isom_get_duration at isom_read.c:971:5 in isomedia.h
// gf_isom_get_first_mdat_start at isom_read.c:4163:5 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_52(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Write the input data to a dummy file
    write_dummy_file(Data, Size);

    // Variables for function calls
    GF_ISOFile *isom_file = NULL;
    u64 top_box_start = 0;
    u64 BytesMissing = 0;
    u32 topBoxType = 0;
    u32 trackNumber = 1; // Arbitrary track number
    GF_Err err;

    // Attempt to open the file progressively
    err = gf_isom_open_progressive_ex("./dummy_file", 0, 0, 0, &isom_file, &BytesMissing, &topBoxType);
    if (err != 0 || !isom_file) {
        return 0; // If opening failed, exit early
    }

    // Fuzz gf_isom_reset_data_offset
    gf_isom_reset_data_offset(isom_file, &top_box_start);

    // Fuzz gf_isom_get_media_data_size
    gf_isom_get_media_data_size(isom_file, trackNumber);

    // Fuzz gf_isom_get_fragmented_duration
    gf_isom_get_fragmented_duration(isom_file);

    // Fuzz gf_isom_get_duration
    gf_isom_get_duration(isom_file);

    // Fuzz gf_isom_get_first_mdat_start
    gf_isom_get_first_mdat_start(isom_file);

    // Cleanup
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

        LLVMFuzzerTestOneInput_52(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    