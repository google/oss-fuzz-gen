// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_set_ipod_compatible at isom_write.c:9114:8 in isomedia.h
// gf_isom_set_fragment_original_duration at movie_fragments.c:3174:8 in isomedia.h
// gf_isom_rtp_set_time_sequence_offset at hint_track.c:292:8 in isomedia.h
// gf_isom_set_media_type at isom_write.c:6307:8 in isomedia.h
// gf_isom_make_interleave_ex at isom_write.c:6151:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
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

int LLVMFuzzerTestOneInput_58(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 4) {
        return 0; // Not enough data to extract necessary parameters
    }

    // Prepare environment
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ_EDIT, NULL);
    if (!isom_file) return 0;

    u32 trackNumber = *(u32 *)(Data);
    u32 trackID = *(u32 *)(Data + sizeof(u32));
    u32 hintDescIndex = *(u32 *)(Data + 2 * sizeof(u32));
    u32 sequenceOffset = *(u32 *)(Data + 3 * sizeof(u32));
    u32 newHandlerType = *(u32 *)(Data + 4 * sizeof(u32));

    GF_Fraction interleaveTime = {1, 1}; // Default fraction
    GF_Err err;

    // Write dummy file
    write_dummy_file(Data, Size);

    // Test gf_isom_set_ipod_compatible
    err = gf_isom_set_ipod_compatible(isom_file, trackNumber);
    if (err) goto cleanup;

    // Test gf_isom_set_fragment_original_duration
    err = gf_isom_set_fragment_original_duration(isom_file, trackID, 1000, 2000);
    if (err) goto cleanup;

    // Test gf_isom_rtp_set_time_sequence_offset
    err = gf_isom_rtp_set_time_sequence_offset(isom_file, trackNumber, hintDescIndex, sequenceOffset);
    if (err) goto cleanup;

    // Test gf_isom_set_media_type
    err = gf_isom_set_media_type(isom_file, trackNumber, newHandlerType);
    if (err) goto cleanup;

    // Test gf_isom_make_interleave_ex
    err = gf_isom_make_interleave_ex(isom_file, &interleaveTime);
    if (err) goto cleanup;

cleanup:
    // Test gf_isom_close
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

        LLVMFuzzerTestOneInput_58(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    