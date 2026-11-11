// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_new_hint_description at hint_track.c:170:8 in isomedia.h
// gf_isom_rtp_set_timescale at hint_track.c:226:8 in isomedia.h
// gf_isom_set_track_matrix at isom_write.c:5254:8 in isomedia.h
// gf_isom_shift_cts_offset at isom_write.c:5187:8 in isomedia.h
// gf_isom_set_ctts_v1 at isom_write.c:7867:8 in isomedia.h
// gf_isom_rtp_packet_set_offset at hint_track.c:653:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_isofile() {
    // Placeholder for actual file creation logic
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ_DUMP, NULL);
    if (!isom_file) {
        // Handle file creation if necessary
    }
    return isom_file;
}

static void free_dummy_isofile(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_156(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3 + sizeof(s32) * 2 + sizeof(u8)) {
        return 0;
    }

    GF_ISOFile *isom_file = create_dummy_isofile();
    if (!isom_file) return 0;

    u32 trackNumber = *((u32*)Data);
    s32 HintTrackVersion = *((s32*)(Data + 4));
    s32 LastCompatibleVersion = *((s32*)(Data + 8));
    u8 Rely = *(Data + 12);
    u32 HintDescriptionIndex = 0;

    gf_isom_new_hint_description(isom_file, trackNumber, HintTrackVersion, LastCompatibleVersion, Rely, &HintDescriptionIndex);

    if (Size >= 16 + sizeof(u32)) {
        u32 TimeScale = *((u32*)(Data + 16));
        gf_isom_rtp_set_timescale(isom_file, trackNumber, HintDescriptionIndex, TimeScale);
    }

    if (Size >= 20 + sizeof(s32) * 9) {
        s32 matrix[9];
        memcpy(matrix, Data + 20, sizeof(s32) * 9);
        gf_isom_set_track_matrix(isom_file, trackNumber, matrix);
    }

    if (Size >= 56 + sizeof(s32)) {
        s32 offset_shift = *((s32*)(Data + 56));
        gf_isom_shift_cts_offset(isom_file, trackNumber, offset_shift);
    }

    if (Size >= 60 + sizeof(u32)) {
        u32 ctts_shift = *((u32*)(Data + 60));
        gf_isom_set_ctts_v1(isom_file, trackNumber, ctts_shift);
    }

    if (Size >= 64 + sizeof(s32)) {
        s32 timeOffset = *((s32*)(Data + 64));
        gf_isom_rtp_packet_set_offset(isom_file, trackNumber, timeOffset);
    }

    free_dummy_isofile(isom_file);
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

        LLVMFuzzerTestOneInput_156(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    