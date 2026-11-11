// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_evte_config_new at sample_descs.c:1846:8 in isomedia.h
// gf_isom_set_sample_references at isom_write.c:9510:8 in isomedia.h
// gf_isom_new_hint_description at hint_track.c:170:8 in isomedia.h
// gf_isom_get_reference at isom_read.c:1237:8 in isomedia.h
// gf_isom_set_sample_flags at isom_write.c:8052:8 in isomedia.h
// gf_isom_rtp_packet_set_offset at hint_track.c:653:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "isomedia.h"

#define DUMMY_FILE "./dummy_file"

static GF_ISOFile* create_dummy_iso_file() {
    // Create a dummy GF_ISOFile with minimal initialization
    GF_ISOFile *iso_file = gf_isom_open(DUMMY_FILE, GF_ISOM_OPEN_WRITE, NULL);
    return iso_file;
}

static void cleanup_iso_file(GF_ISOFile *iso_file) {
    if (iso_file) {
        gf_isom_close(iso_file);
    }
}

int LLVMFuzzerTestOneInput_158(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isom_file = create_dummy_iso_file();
    if (!isom_file) return 0;

    // Prepare dummy file
    FILE *file = fopen(DUMMY_FILE, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }

    u32 trackNumber = 1;
    u32 outDescriptionIndex = 0;
    u32 sampleNumber = 1;
    s32 ID = 1;
    u32 nb_refs = 1;
    s32 refs[] = {1};
    s32 HintTrackVersion = 1;
    s32 LastCompatibleVersion = 1;
    u8 Rely = 0;
    u32 HintDescriptionIndex = 0;
    u32 referenceType = 0;
    u32 referenceIndex = 1;
    u32 refTrack = 0;
    u32 isLeading = 0;
    u32 dependsOn = 0;
    u32 dependedOn = 0;
    u32 redundant = 0;
    s32 timeOffset = 0;

    // Fuzz gf_isom_evte_config_new
    gf_isom_evte_config_new(isom_file, trackNumber, &outDescriptionIndex);

    // Fuzz gf_isom_set_sample_references
    gf_isom_set_sample_references(isom_file, trackNumber, sampleNumber, ID, nb_refs, refs);

    // Fuzz gf_isom_new_hint_description
    gf_isom_new_hint_description(isom_file, trackNumber, HintTrackVersion, LastCompatibleVersion, Rely, &HintDescriptionIndex);

    // Fuzz gf_isom_get_reference
    gf_isom_get_reference(isom_file, trackNumber, referenceType, referenceIndex, &refTrack);

    // Fuzz gf_isom_set_sample_flags
    gf_isom_set_sample_flags(isom_file, trackNumber, sampleNumber, isLeading, dependsOn, dependedOn, redundant);

    // Fuzz gf_isom_rtp_packet_set_offset
    gf_isom_rtp_packet_set_offset(isom_file, trackNumber, timeOffset);

    cleanup_iso_file(isom_file);
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

        LLVMFuzzerTestOneInput_158(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    