// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_set_composition_offset_mode at isom_write.c:8001:8 in isomedia.h
// gf_isom_get_icc_profile at isom_read.c:4019:8 in isomedia.h
// gf_isom_set_pixel_aspect_ratio at isom_write.c:1847:8 in isomedia.h
// gf_isom_remove_edits at isom_write.c:2797:8 in isomedia.h
// gf_isom_allocate_sidx at movie_fragments.c:1347:8 in isomedia.h
// gf_isom_remove_track_reference at isom_write.c:5051:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
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

int LLVMFuzzerTestOneInput_200(const uint8_t *Data, size_t Size) {
    // Ensure we have enough data for trackNumber and use_negative_offsets
    if (Size < sizeof(u32) + sizeof(Bool)) {
        return 0;
    }

    // Prepare dummy ISO file
    GF_ISOFile *isoFile = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    if (!isoFile) return 0;

    // Extract trackNumber and use_negative_offsets from input data
    u32 trackNumber = *(u32 *)Data;
    Bool use_negative_offsets = *(Bool *)(Data + sizeof(u32));

    // Fuzz gf_isom_set_composition_offset_mode
    gf_isom_set_composition_offset_mode(isoFile, trackNumber, use_negative_offsets);

    // Fuzz gf_isom_get_icc_profile
    u32 sampleDescriptionIndex = 1;
    Bool icc_restricted;
    const u8 *icc;
    u32 icc_size;
    gf_isom_get_icc_profile(isoFile, trackNumber, sampleDescriptionIndex, &icc_restricted, &icc, &icc_size);

    // Fuzz gf_isom_set_pixel_aspect_ratio
    s32 hSpacing = 1;
    s32 vSpacing = 1;
    Bool force_par = GF_TRUE;
    gf_isom_set_pixel_aspect_ratio(isoFile, trackNumber, sampleDescriptionIndex, hSpacing, vSpacing, force_par);

    // Fuzz gf_isom_remove_edits
    gf_isom_remove_edits(isoFile, trackNumber);

    // Fuzz gf_isom_allocate_sidx
    u32 nb_segs = 1;
    u32 start_range = 0, end_range = 0;
    gf_isom_allocate_sidx(isoFile, 0, GF_FALSE, nb_segs, NULL, &start_range, &end_range, GF_FALSE);

    // Fuzz gf_isom_remove_track_reference
    u32 ref_type = 0;
    gf_isom_remove_track_reference(isoFile, trackNumber, ref_type);

    // Cleanup
    gf_isom_close(isoFile);

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

        LLVMFuzzerTestOneInput_200(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    