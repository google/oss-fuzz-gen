#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static void fuzz_gf_isom_remove_cenc_seig_sample_group(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32)) return;
    u32 trackNumber = *(u32 *)Data;
    gf_isom_remove_cenc_seig_sample_group(isom_file, trackNumber);
}

static void fuzz_gf_isom_get_adobe_protection_info(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(u32)) return;
    u32 trackNumber = *(u32 *)Data;
    u32 sampleDescriptionIndex = *(u32 *)(Data + sizeof(u32));
    u32 outOriginalFormat, outSchemeType, outSchemeVersion;
    const char *outMetadata;
    gf_isom_get_adobe_protection_info(isom_file, trackNumber, sampleDescriptionIndex, &outOriginalFormat, &outSchemeType, &outSchemeVersion, &outMetadata);
}

static void fuzz_gf_isom_set_mpegh_compatible_profiles(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < 3 * sizeof(u32)) return;
    u32 trackNumber = *(u32 *)Data;
    u32 sampleDescriptionIndex = *(u32 *)(Data + sizeof(u32));
    u32 nb_compatible_profiles = *(u32 *)(Data + 2 * sizeof(u32));
    const u32 *profiles = NULL;
    if (Size >= 3 * sizeof(u32) + nb_compatible_profiles * sizeof(u32)) {
        profiles = (const u32 *)(Data + 3 * sizeof(u32));
    }
    gf_isom_set_mpegh_compatible_profiles(isom_file, trackNumber, sampleDescriptionIndex, profiles, nb_compatible_profiles);
}

static void fuzz_gf_isom_get_text_description(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(u32)) return;
    u32 trackNumber = *(u32 *)Data;
    u32 sampleDescriptionIndex = *(u32 *)(Data + sizeof(u32));
    GF_TextSampleDescriptor *out_desc = NULL;
    gf_isom_get_text_description(isom_file, trackNumber, sampleDescriptionIndex, &out_desc);
    if (out_desc) {
        free(out_desc);
    }
}

static void fuzz_gf_isom_remove_stream_description(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(u32)) return;
    u32 trackNumber = *(u32 *)Data;
    u32 sampleDescriptionIndex = *(u32 *)(Data + sizeof(u32));
    gf_isom_remove_stream_description(isom_file, trackNumber, sampleDescriptionIndex);
}

static void fuzz_gf_isom_remove_chapter(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(u32)) return;
    u32 trackNumber = *(u32 *)Data;
    u32 index = *(u32 *)(Data + sizeof(u32));
    gf_isom_remove_chapter(isom_file, trackNumber, index);
}

int LLVMFuzzerTestOneInput_135(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    fuzz_gf_isom_remove_cenc_seig_sample_group(isom_file, Data, Size);
    fuzz_gf_isom_get_adobe_protection_info(isom_file, Data, Size);
    fuzz_gf_isom_set_mpegh_compatible_profiles(isom_file, Data, Size);
    fuzz_gf_isom_get_text_description(isom_file, Data, Size);
    fuzz_gf_isom_remove_stream_description(isom_file, Data, Size);
    fuzz_gf_isom_remove_chapter(isom_file, Data, Size);

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

    LLVMFuzzerTestOneInput_135(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
