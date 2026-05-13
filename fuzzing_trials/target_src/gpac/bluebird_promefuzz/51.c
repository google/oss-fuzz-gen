#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_51(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3) return 0;

    // Prepare dummy file
    write_dummy_file(Data, Size);

    // Initialize variables
    const char *tmp_dir = NULL; // Assuming no temporary directory needed
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, tmp_dir);
    if (!isom_file) return 0;

    u32 trackNumber = *((u32*)Data);
    u32 newTrackID = *((u32*)(Data + sizeof(u32)));

    // Fuzz gf_isom_set_track_id
    gf_isom_set_track_id(isom_file, trackNumber, newTrackID);

    // Fuzz gf_isom_fragment_add_sample_references
    if (Size >= sizeof(u32) * 4) {
        s32 refID = *((s32*)(Data + sizeof(u32) * 2));
        u32 nb_refs = *((u32*)(Data + sizeof(u32) * 3));
        s32 *refs = NULL;
        if (nb_refs > 0 && Size >= sizeof(u32) * (4 + nb_refs)) {
            refs = (s32*)(Data + sizeof(u32) * 4);
        }
        gf_isom_fragment_add_sample_references(isom_file, newTrackID, refID, nb_refs, refs);
    }

    // Fuzz gf_isom_set_sample_references
    if (Size >= sizeof(u32) * 5) {
        u32 sampleNumber = *((u32*)(Data + sizeof(u32) * 4));
        s32 ID = *((s32*)(Data + sizeof(u32) * 5));
        u32 nb_refs = *((u32*)(Data + sizeof(u32) * 6));
        s32 *refs = NULL;
        if (nb_refs > 0 && Size >= sizeof(u32) * (7 + nb_refs)) {
            refs = (s32*)(Data + sizeof(u32) * 7);
        }
        gf_isom_set_sample_references(isom_file, trackNumber, sampleNumber, ID, nb_refs, refs);
    }

    // Fuzz gf_isom_get_sample_flags
    if (Size >= sizeof(u32) * 6) {
        u32 sampleNumber = *((u32*)(Data + sizeof(u32) * 5));
        u32 is_leading, dependsOn, dependedOn, redundant;
        gf_isom_get_sample_flags(isom_file, trackNumber, sampleNumber, &is_leading, &dependsOn, &dependedOn, &redundant);
    }

    // Fuzz gf_isom_get_clean_aperture
    if (Size >= sizeof(u32) * 7) {
        u32 sampleDescriptionIndex = *((u32*)(Data + sizeof(u32) * 6));
        u32 cleanApertureWidthN, cleanApertureWidthD, cleanApertureHeightN, cleanApertureHeightD;
        s32 horizOffN, vertOffN;
        u32 horizOffD, vertOffD;
        gf_isom_get_clean_aperture(isom_file, trackNumber, sampleDescriptionIndex,
                                   &cleanApertureWidthN, &cleanApertureWidthD,
                                   &cleanApertureHeightN, &cleanApertureHeightD,
                                   &horizOffN, &horizOffD, &vertOffN, &vertOffD);
    }

    // Fuzz gf_isom_get_reference
    if (Size >= sizeof(u32) * 8) {
        u32 referenceType = *((u32*)(Data + sizeof(u32) * 7));
        u32 referenceIndex = *((u32*)(Data + sizeof(u32) * 8));
        u32 refTrack;
        gf_isom_get_reference(isom_file, trackNumber, referenceType, referenceIndex, &refTrack);
    }

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

    LLVMFuzzerTestOneInput_51(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
