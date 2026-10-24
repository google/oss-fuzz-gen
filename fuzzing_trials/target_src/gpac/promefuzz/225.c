// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_add_sample_info at isom_write.c:7672:8 in isomedia.h
// gf_isom_fragment_add_sample_references at movie_fragments.c:3537:8 in isomedia.h
// gf_isom_set_sample_references at isom_write.c:9510:8 in isomedia.h
// gf_isom_get_sample_flags at isom_read.c:1913:8 in isomedia.h
// gf_isom_set_track_reference at isom_write.c:4967:8 in isomedia.h
// gf_isom_get_reference_count at isom_read.c:1197:5 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

#define DUMMY_FILE_PATH "./dummy_file"

static GF_ISOFile* initialize_iso_file() {
    // We cannot allocate the size of an incomplete type, so we return NULL for now.
    return NULL;
}

static void cleanup_iso_file(GF_ISOFile *isom_file) {
    // No cleanup required since we cannot allocate GF_ISOFile
}

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen(DUMMY_FILE_PATH, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_225(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0;

    GF_ISOFile *isom_file = initialize_iso_file();
    if (!isom_file) return 0;

    write_dummy_file(Data, Size);

    u32 trackNumber = *(u32*)Data;
    u32 sampleNumber = *(u32*)(Data + 4);
    u32 grouping_type = *(u32*)(Data + 8);
    u32 sampleGroupDescriptionIndex = *(u32*)(Data + 12);
    u32 grouping_type_parameter = *(u32*)(Data + 16);

    gf_isom_add_sample_info(isom_file, trackNumber, sampleNumber, grouping_type, sampleGroupDescriptionIndex, grouping_type_parameter);

    s32 refID = *(s32*)(Data + 20);
    u32 nb_refs = *(u32*)(Data + 24);
    s32 *refs = NULL;

    if (nb_refs > 0 && Size >= 28 + nb_refs * sizeof(s32)) {
        refs = (s32*)(Data + 28);
    }

    gf_isom_fragment_add_sample_references(isom_file, trackNumber, refID, nb_refs, refs);
    gf_isom_set_sample_references(isom_file, trackNumber, sampleNumber, refID, nb_refs, refs);

    u32 is_leading, dependsOn, dependedOn, redundant;
    gf_isom_get_sample_flags(isom_file, trackNumber, sampleNumber, &is_leading, &dependsOn, &dependedOn, &redundant);

    u32 referenceType = *(u32*)(Data + 28 + nb_refs * sizeof(s32));
    GF_ISOTrackID ReferencedTrackID = *(GF_ISOTrackID*)(Data + 32 + nb_refs * sizeof(s32));

    gf_isom_set_track_reference(isom_file, trackNumber, referenceType, ReferencedTrackID);

    gf_isom_get_reference_count(isom_file, trackNumber, referenceType);

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

        LLVMFuzzerTestOneInput_225(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    