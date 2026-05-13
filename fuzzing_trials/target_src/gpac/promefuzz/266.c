// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_has_track_reference at isom_read.c:1295:5 in isomedia.h
// gf_isom_get_mpeg4_subtype at isom_read.c:1671:5 in isomedia.h
// gf_isom_set_default_sync_track at isom_read.c:4209:6 in isomedia.h
// gf_isom_get_sample_size at isom_read.c:2007:5 in isomedia.h
// gf_isom_enum_track_references at isom_read.c:1219:22 in isomedia.h
// gf_isom_av1_config_get at avc_ext.c:2605:15 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

static void cleanup_iso_file(GF_ISOFile *iso_file) {
    // Cleanup logic if any, based on how iso_file is initialized
    // Currently, there's no known structure to free specific members
    free(iso_file);
}

int LLVMFuzzerTestOneInput_266(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 4) return 0;

    GF_ISOFile *iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!iso_file) return 0;

    u32 trackNumber = *((u32 *)Data);
    u32 referenceType = *((u32 *)(Data + sizeof(u32)));
    GF_ISOTrackID refTrackID = *((GF_ISOTrackID *)(Data + 2 * sizeof(u32)));

    u32 refIndex = gf_isom_has_track_reference(iso_file, trackNumber, referenceType, refTrackID);

    u32 sampleDescriptionIndex = *((u32 *)(Data + 3 * sizeof(u32)));
    u32 mpeg4Subtype = gf_isom_get_mpeg4_subtype(iso_file, trackNumber, sampleDescriptionIndex);

    gf_isom_set_default_sync_track(iso_file, trackNumber);

    u32 sampleNumber = *((u32 *)(Data + 4 * sizeof(u32)));
    u32 sampleSize = gf_isom_get_sample_size(iso_file, trackNumber, sampleNumber);

    u32 referenceCount;
    const GF_ISOTrackID *trackIDs = gf_isom_enum_track_references(iso_file, trackNumber, 0, &referenceType, &referenceCount);

    GF_AV1Config *av1Config = gf_isom_av1_config_get(iso_file, trackNumber, sampleDescriptionIndex);
    if (av1Config) {
        free(av1Config);
    }

    gf_isom_close(iso_file);
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

        LLVMFuzzerTestOneInput_266(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    