#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* initialize_isofile(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return NULL;

    // Write Data to a dummy file
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        gf_isom_close(isom_file);
        return NULL;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    return isom_file;
}

static void cleanup_isofile(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
        remove("./dummy_file");
    }
}

int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0; // Ensure there is enough data

    GF_ISOFile *isom_file = initialize_isofile(Data, Size);
    if (!isom_file) return 0;

    u32 trackNumber = Data[0];
    u32 referenceType = Data[1];
    u32 refTrackID = Data[2];
    u32 sampleDescriptionIndex = Data[3];

    // Fuzz gf_isom_has_track_reference
    u32 ref_index = gf_isom_has_track_reference(isom_file, trackNumber, referenceType, refTrackID);
    if (ref_index != 0) {
        // Handle non-zero reference index case
    }

    // Fuzz gf_isom_get_sample_count
    u32 sample_count = gf_isom_get_sample_count(isom_file, trackNumber);
    if (sample_count != 0) {
        // Handle non-zero sample count case
    }

    // Fuzz gf_isom_get_mpeg4_subtype
    u32 mpeg4_subtype = gf_isom_get_mpeg4_subtype(isom_file, trackNumber, sampleDescriptionIndex);
    if (mpeg4_subtype != 0) {
        // Handle valid MPEG-4 subtype case
    }

    // Fuzz gf_isom_set_default_sync_track
    gf_isom_set_default_sync_track(isom_file, trackNumber);

    // Fuzz gf_isom_enum_track_references
    u32 referenceTypeOut;
    u32 referenceCount;
    const GF_ISOTrackID *track_ids = gf_isom_enum_track_references(isom_file, trackNumber, 0, &referenceTypeOut, &referenceCount);
    if (track_ids) {
        // Handle non-NULL track IDs case
    }

    // Fuzz gf_isom_av1_config_get
    GF_AV1Config *av1_config = gf_isom_av1_config_get(isom_file, trackNumber, sampleDescriptionIndex);
    if (av1_config) {
        // Handle valid AV1 config case
        free(av1_config); // Assuming user is responsible for freeing
    }

    cleanup_isofile(isom_file);
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

    LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
