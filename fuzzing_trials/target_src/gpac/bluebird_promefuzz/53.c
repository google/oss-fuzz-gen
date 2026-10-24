#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* open_dummy_iso_file() {
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return isom_file;
}

static void close_dummy_iso_file(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_53(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 6) return 0; // Ensure enough data for trackNumber, sampleNumber, etc.

    GF_ISOFile *isom_file = open_dummy_iso_file();
    if (!isom_file) return 0;

    u32 trackNumber = *((u32*)Data);
    u32 sampleNumber = *((u32*)(Data + sizeof(u32)));
    u32 grouping_type = *((u32*)(Data + 2 * sizeof(u32)));
    u32 grouping_type_parameter = *((u32*)(Data + 3 * sizeof(u32)));
    u32 index = *((u32*)(Data + 4 * sizeof(u32)));
    u32 udta_idx = *((u32*)(Data + 5 * sizeof(u32)));

    u32 sampleGroupDescIndex;
    u32 UserDataType;
    bin128 UUID;

    // Fuzz gf_isom_remove_sample
    gf_isom_remove_sample(isom_file, trackNumber, sampleNumber);

    // Fuzz gf_isom_get_sample_to_group_info
    gf_isom_get_sample_to_group_info(isom_file, trackNumber, sampleNumber, grouping_type, grouping_type_parameter, &sampleGroupDescIndex);

    // Fuzz gf_isom_remove_sample_group
    gf_isom_remove_sample_group(isom_file, trackNumber, grouping_type);

    // Fuzz gf_isom_remove_chapter
    gf_isom_remove_chapter(isom_file, trackNumber, index);

    // Fuzz gf_isom_get_udta_type
    gf_isom_get_udta_type(isom_file, trackNumber, udta_idx, &UserDataType, UUID);

    // Fuzz gf_isom_remove_cenc_senc_box
    gf_isom_remove_cenc_senc_box(isom_file, trackNumber);

    close_dummy_iso_file(isom_file);
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

    LLVMFuzzerTestOneInput_53(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
