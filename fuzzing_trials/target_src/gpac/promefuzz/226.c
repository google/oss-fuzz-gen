// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_fragment_add_sample_references at movie_fragments.c:3537:8 in isomedia.h
// gf_isom_add_sample_info at isom_write.c:7672:8 in isomedia.h
// gf_isom_set_sample_references at isom_write.c:9510:8 in isomedia.h
// gf_isom_get_sample_flags at isom_read.c:1913:8 in isomedia.h
// gf_isom_set_track_reference at isom_write.c:4967:8 in isomedia.h
// gf_isom_get_reference_count at isom_read.c:1197:5 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "isomedia.h"

#define DUMMY_FILE_PATH "./dummy_file"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen(DUMMY_FILE_PATH, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_226(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 9) {
        return 0;
    }
    
    // Prepare dummy file
    write_dummy_file(Data, Size);

    // Open the dummy file
    GF_ISOFile *isom_file = gf_isom_open(DUMMY_FILE_PATH, GF_ISOM_OPEN_WRITE, NULL);
    if (!isom_file) return 0;

    // Extract values from input data
    GF_ISOTrackID trackID = *(GF_ISOTrackID *)(Data);
    u32 sampleID = *(u32 *)(Data + sizeof(GF_ISOTrackID));
    u32 nb_refs = *(u32 *)(Data + sizeof(GF_ISOTrackID) + sizeof(u32));
    s32 *refs = (s32 *)(Data + sizeof(u32) * 3);

    // Call gf_isom_fragment_add_sample_references
    gf_isom_fragment_add_sample_references(isom_file, trackID, sampleID, nb_refs, refs);

    // Call gf_isom_add_sample_info
    u32 sampleNumber = *(u32 *)(Data + sizeof(u32) * 4);
    u32 grouping_type = *(u32 *)(Data + sizeof(u32) * 5);
    u32 sampleGroupDescriptionIndex = *(u32 *)(Data + sizeof(u32) * 6);
    u32 grouping_type_parameter = *(u32 *)(Data + sizeof(u32) * 7);

    gf_isom_add_sample_info(isom_file, trackID, sampleNumber, grouping_type, sampleGroupDescriptionIndex, grouping_type_parameter);

    // Call gf_isom_set_sample_references
    gf_isom_set_sample_references(isom_file, trackID, sampleNumber, sampleID, nb_refs, refs);

    // Call gf_isom_get_sample_flags
    u32 is_leading, dependsOn, dependedOn, redundant;
    gf_isom_get_sample_flags(isom_file, trackID, sampleNumber, &is_leading, &dependsOn, &dependedOn, &redundant);

    // Call gf_isom_set_track_reference
    u32 referenceType = *(u32 *)(Data + sizeof(u32) * 8);
    gf_isom_set_track_reference(isom_file, trackID, referenceType, trackID);

    // Call gf_isom_get_reference_count
    gf_isom_get_reference_count(isom_file, trackID, referenceType);

    // Cleanup
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

        LLVMFuzzerTestOneInput_226(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    