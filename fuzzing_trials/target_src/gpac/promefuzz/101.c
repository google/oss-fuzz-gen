// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open_progressive_ex at isom_read.c:435:8 in isomedia.h
// gf_isom_get_creation_time at isom_read.c:994:8 in isomedia.h
// gf_isom_set_fragment_reference_time at movie_fragments.c:2552:8 in isomedia.h
// gf_isom_reset_data_offset at isom_read.c:3151:8 in isomedia.h
// gf_isom_get_file_offset_for_time at isom_read.c:6170:8 in isomedia.h
// gf_isom_get_sidx_duration at isom_read.c:6196:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_101(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u64) * 2 + sizeof(Double)) return 0;

    // Write data to a dummy file
    write_dummy_file(Data, Size);

    // Test gf_isom_open_progressive_ex
    GF_ISOFile *isom_file = NULL;
    u64 BytesMissing = 0;
    u32 topBoxType = 0;
    u64 start_range = 0;
    u64 end_range = Size;
    Bool enable_frag_templates = 1;
    GF_Err err = gf_isom_open_progressive_ex("./dummy_file", start_range, end_range, enable_frag_templates, &isom_file, &BytesMissing, &topBoxType);
    if (err != GF_OK || !isom_file) return 0;

    // Test gf_isom_get_creation_time
    u64 creationTime = 0;
    u64 modificationTime = 0;
    gf_isom_get_creation_time(isom_file, &creationTime, &modificationTime);

    // Test gf_isom_set_fragment_reference_time
    GF_ISOTrackID reference_track_ID = 1;
    u64 ntp = *((u64 *)Data);
    u64 timestamp = *((u64 *)(Data + sizeof(u64)));
    Bool at_mux = 1;
    gf_isom_set_fragment_reference_time(isom_file, reference_track_ID, ntp, timestamp, at_mux);

    // Test gf_isom_reset_data_offset
    u64 top_box_start = 0;
    gf_isom_reset_data_offset(isom_file, &top_box_start);

    // Test gf_isom_get_file_offset_for_time
    Double start_time = *((Double *)(Data + sizeof(u64) * 2));
    u64 offset = 0;
    gf_isom_get_file_offset_for_time(isom_file, start_time, &offset);

    // Test gf_isom_get_sidx_duration
    u64 sidx_dur = 0;
    u32 sidx_timescale = 0;
    gf_isom_get_sidx_duration(isom_file, &sidx_dur, &sidx_timescale);

    // Cleanup
    if (isom_file) {
        // Assuming there is a function to close the ISO file, e.g., gf_isom_close
        // gf_isom_close(isom_file);
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

        LLVMFuzzerTestOneInput_101(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    