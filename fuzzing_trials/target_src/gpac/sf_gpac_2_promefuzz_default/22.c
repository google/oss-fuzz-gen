// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_reset_data_offset at isom_read.c:3151:8 in isomedia.h
// gf_isom_get_media_time at isom_read.c:1342:8 in isomedia.h
// gf_isom_remove_sample_group at isom_write.c:7751:8 in isomedia.h
// gf_isom_set_vexu at isom_write.c:500:8 in isomedia.h
// gf_isom_set_traf_mss_timeext at movie_fragments.c:2564:8 in isomedia.h
// gf_isom_hint_max_chunk_duration at isom_write.c:6032:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
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

int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    // Create a dummy GF_ISOFile
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    u64 top_box_start = 0;
    u64 media_time = 0;
    u64 decode_traf_time = 0;
    u64 traf_duration = 0;
    u32 trackNumber = 0;
    u32 movieTime = 0;
    u32 grouping_type = 0;
    u32 hero_eye = 0;
    u32 reference_track_ID = 0;
    u32 maxChunkDur = 0;

    // Write the input data to a dummy file
    write_dummy_file(Data, Size);

    // Invoke gf_isom_reset_data_offset
    gf_isom_reset_data_offset(isom_file, &top_box_start);

    // Invoke gf_isom_get_media_time
    gf_isom_get_media_time(isom_file, trackNumber, movieTime, &media_time);

    // Invoke gf_isom_remove_sample_group
    gf_isom_remove_sample_group(isom_file, trackNumber, grouping_type);

    // Invoke gf_isom_set_vexu
    gf_isom_set_vexu(isom_file, hero_eye);

    // Invoke gf_isom_set_traf_mss_timeext
    gf_isom_set_traf_mss_timeext(isom_file, reference_track_ID, decode_traf_time, traf_duration);

    // Invoke gf_isom_hint_max_chunk_duration
    gf_isom_hint_max_chunk_duration(isom_file, trackNumber, maxChunkDur);

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

        LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    