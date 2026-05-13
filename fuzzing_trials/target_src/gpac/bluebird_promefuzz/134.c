#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "/src/gpac/include/gpac/isomedia.h"

#define DUMMY_ISO_FILE_SIZE 1024

static GF_ISOFile* create_dummy_iso_file() {
    // Allocate a dummy buffer to simulate the ISO file
    GF_ISOFile *iso_file = (GF_ISOFile *)malloc(DUMMY_ISO_FILE_SIZE);
    if (!iso_file) return NULL;
    memset(iso_file, 0, DUMMY_ISO_FILE_SIZE);
    return iso_file;
}

static void destroy_dummy_iso_file(GF_ISOFile *iso_file) {
    if (iso_file) {
        free(iso_file);
    }
}

int LLVMFuzzerTestOneInput_134(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 5) return 0;

    GF_ISOFile *iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    // Fuzz gf_isom_guess_specification
    gf_isom_guess_specification(iso_file);

    // Fuzz gf_isom_has_track_reference
    u32 trackNumber = *(u32 *)Data;
    u32 referenceType = *(u32 *)(Data + sizeof(u32));
    GF_ISOTrackID refTrackID = *(GF_ISOTrackID *)(Data + 2 * sizeof(u32));
    gf_isom_has_track_reference(iso_file, trackNumber, referenceType, refTrackID);

    // Fuzz gf_isom_get_generic_sample_description
    u32 sampleDescriptionIndex = *(u32 *)(Data + 3 * sizeof(u32));
    gf_isom_get_generic_sample_description(iso_file, trackNumber, sampleDescriptionIndex);

    // Fuzz gf_isom_get_mpeg4_subtype
    gf_isom_get_mpeg4_subtype(iso_file, trackNumber, sampleDescriptionIndex);

    // Fuzz gf_isom_get_edits_count
    gf_isom_get_edits_count(iso_file, trackNumber);

    // Fuzz gf_isom_enum_track_references
    u32 idx = *(u32 *)(Data + 4 * sizeof(u32));
    u32 referenceTypeOut, referenceCountOut;
    gf_isom_enum_track_references(iso_file, trackNumber, idx, &referenceTypeOut, &referenceCountOut);

    destroy_dummy_iso_file(iso_file);
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

    LLVMFuzzerTestOneInput_134(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
