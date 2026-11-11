// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_get_current_tfdt at isom_read.c:5822:5 in isomedia.h
// gf_isom_segment_get_fragment_size at isom_read.c:927:5 in isomedia.h
// gf_isom_get_sample_dts at isom_read.c:2141:5 in isomedia.h
// gf_isom_reset_sample_count at isom_read.c:5005:6 in isomedia.h
// gf_isom_get_smooth_next_tfdt at isom_read.c:5835:5 in isomedia.h
// gf_isom_segment_get_track_fragment_decode_time at isom_read.c:908:5 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* open_iso_file() {
    GF_ISOFile *file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return file;
}

static void close_iso_file(GF_ISOFile *file) {
    if (file) {
        gf_isom_close(file);
    }
}

int LLVMFuzzerTestOneInput_67(const uint8_t *Data, size_t Size) {
    FILE *dummy_file = fopen("./dummy_file", "wb");
    if (!dummy_file) {
        return 0;
    }
    fwrite(Data, 1, Size, dummy_file);
    fclose(dummy_file);

    GF_ISOFile *isom_file = open_iso_file();
    if (!isom_file) return 0;

    // Fuzzing gf_isom_get_current_tfdt
    u32 trackNumber = Size > 4 ? *(u32*)Data : 0;
    u64 tfdt = gf_isom_get_current_tfdt(isom_file, trackNumber);

    // Fuzzing gf_isom_segment_get_fragment_size
    u32 moof_index = Size > 8 ? *(u32*)(Data + 4) : 0;
    u32 moof_size = 0;
    u64 fragment_size = gf_isom_segment_get_fragment_size(isom_file, moof_index, &moof_size);

    // Fuzzing gf_isom_get_sample_dts
    u32 sampleNumber = Size > 12 ? *(u32*)(Data + 8) : 0;
    u64 dts = gf_isom_get_sample_dts(isom_file, trackNumber, sampleNumber);

    // Fuzzing gf_isom_reset_sample_count
    gf_isom_reset_sample_count(isom_file);

    // Fuzzing gf_isom_get_smooth_next_tfdt
    u64 smooth_next_tfdt = gf_isom_get_smooth_next_tfdt(isom_file, trackNumber);

    // Fuzzing gf_isom_segment_get_track_fragment_decode_time
    u32 traf_index = Size > 16 ? *(u32*)(Data + 12) : 0;
    u64 decode_time = 0;
    u32 track_id = gf_isom_segment_get_track_fragment_decode_time(isom_file, moof_index, traf_index, &decode_time);

    close_iso_file(isom_file);
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

        LLVMFuzzerTestOneInput_67(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    