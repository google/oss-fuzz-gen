// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_get_sample_for_media_time at isom_read.c:2192:8 in isomedia.h
// gf_isom_refresh_size_info at stbl_write.c:2299:8 in isomedia.h
// gf_isom_reset_data_offset at isom_read.c:3151:8 in isomedia.h
// gf_isom_remove_edits at isom_write.c:2916:8 in isomedia.h
// gf_isom_force_track_duration at isom_write.c:957:8 in isomedia.h
// gf_isom_update_sample_reference at isom_write.c:1538:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static void create_dummy_file(const char *filename, const uint8_t *data, size_t size) {
    FILE *file = fopen(filename, "wb");
    if (file) {
        fwrite(data, 1, size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    // Create a dummy file for testing
    const char *dummy_file = "./dummy_file";
    create_dummy_file(dummy_file, Data, Size);

    // Initialize variables for API functions
    GF_ISOFile *isom_file = gf_isom_open(dummy_file, GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    u32 trackNumber = Size > 0 ? Data[0] : 0;
    u64 desiredTime = Size > 1 ? Data[1] : 0;
    u32 sampleDescriptionIndex = 0;
    GF_ISOSample *sample = NULL;
    u32 sample_number = 0;
    u64 data_offset = 0;
    GF_ISOSearchMode searchMode = 0;

    // Fuzz gf_isom_get_sample_for_media_time
    gf_isom_get_sample_for_media_time(isom_file, trackNumber, desiredTime, &sampleDescriptionIndex, searchMode, &sample, &sample_number, &data_offset);

    // Fuzz gf_isom_refresh_size_info
    gf_isom_refresh_size_info(isom_file, trackNumber);

    // Fuzz gf_isom_reset_data_offset
    gf_isom_reset_data_offset(isom_file, &data_offset);

    // Fuzz gf_isom_remove_edits
    gf_isom_remove_edits(isom_file, trackNumber);

    // Fuzz gf_isom_force_track_duration
    gf_isom_force_track_duration(isom_file, trackNumber, desiredTime);

    // Prepare sample for gf_isom_update_sample_reference
    GF_ISOSample sample_data;
    sample_data.dataLength = Size > 2 ? Data[2] : 0;
    sample_data.data = NULL;

    // Fuzz gf_isom_update_sample_reference
    gf_isom_update_sample_reference(isom_file, trackNumber, sample_number, &sample_data, data_offset);

    // Clean up
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

        LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    