// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_get_media_type at isom_read.c:1586:5 in isomedia.h
// gf_isom_guess_specification at isom_read.c:4276:5 in isomedia.h
// gf_isom_is_media_encrypted at drm_sample.c:193:5 in isomedia.h
// gf_isom_get_media_subtype at isom_read.c:1644:5 in isomedia.h
// gf_isom_get_avc_svc_type at avc_ext.c:2682:16 in isomedia.h
// gf_isom_get_track_by_id at isom_read.c:807:5 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // This function creates a dummy GF_ISOFile structure for testing purposes.
    // Since GF_ISOFile is an incomplete type, we cannot allocate it directly.
    // Instead, assume we have a function to create an ISO file in the library.
    GF_ISOFile *isoFile = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return isoFile;
}

static void cleanup_iso_file(GF_ISOFile *isoFile) {
    // Clean up the allocated GF_ISOFile structure
    if (isoFile) {
        gf_isom_close(isoFile);
    }
}

int LLVMFuzzerTestOneInput_181(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32)) return 0;

    GF_ISOFile *isoFile = create_dummy_iso_file();
    if (!isoFile) return 0;

    u32 trackNumber = *(u32 *)Data;
    u32 sampleDescriptionIndex = (Size > sizeof(u32)) ? *(u32 *)(Data + sizeof(u32)) : 0;

    // Fuzz gf_isom_get_media_type
    u32 mediaType = gf_isom_get_media_type(isoFile, trackNumber);

    // Fuzz gf_isom_guess_specification
    u32 specification = gf_isom_guess_specification(isoFile);

    // Fuzz gf_isom_is_media_encrypted
    u32 isEncrypted = gf_isom_is_media_encrypted(isoFile, trackNumber, sampleDescriptionIndex);

    // Fuzz gf_isom_get_media_subtype
    u32 mediaSubtype = gf_isom_get_media_subtype(isoFile, trackNumber, sampleDescriptionIndex);

    // Fuzz gf_isom_get_avc_svc_type
    GF_ISOMAVCType avcType = gf_isom_get_avc_svc_type(isoFile, trackNumber, sampleDescriptionIndex);

    // Fuzz gf_isom_get_track_by_id
    u32 trackID = (Size > 2 * sizeof(u32)) ? *(u32 *)(Data + 2 * sizeof(u32)) : 0;
    u32 trackNum = gf_isom_get_track_by_id(isoFile, trackID);

    cleanup_iso_file(isoFile);
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

        LLVMFuzzerTestOneInput_181(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    