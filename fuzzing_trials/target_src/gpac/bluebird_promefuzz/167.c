#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "/src/gpac/include/gpac/isomedia.h"

int LLVMFuzzerTestOneInput_167(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3) {
        return 0; // Not enough data to extract trackNumber, sampleNumber, and sampleDescriptionIndex
    }

    // Create a dummy file to simulate the ISO file interaction
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Open the dummy file using gpac API
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) {
        return 0;
    }

    u32 trackNumber = *((u32 *)Data);
    u32 sampleNumber = *((u32 *)(Data + sizeof(u32)));
    u32 sampleDescriptionIndex = *((u32 *)(Data + 2 * sizeof(u32)));

    // Fuzz gf_isom_remove_sample
    gf_isom_remove_sample(isom_file, trackNumber, sampleNumber);

    // Fuzz gf_isom_remove_cenc_seig_sample_group
    gf_isom_remove_cenc_seig_sample_group(isom_file, trackNumber);

    // Fuzz gf_isom_set_sample_cenc_default_group
    gf_isom_set_sample_cenc_default_group(isom_file, trackNumber, sampleNumber);

    // Fuzz gf_isom_add_desc_to_description
    GF_Descriptor desc;
    gf_isom_add_desc_to_description(isom_file, trackNumber, sampleDescriptionIndex, &desc);

    // Fuzz gf_isom_get_track_switch_group_count
    u32 alternateGroupID = 0;
    u32 nb_groups = 0;
    gf_isom_get_track_switch_group_count(isom_file, trackNumber, &alternateGroupID, &nb_groups);

    // Fuzz gf_isom_remove_cenc_senc_box
    gf_isom_remove_cenc_senc_box(isom_file, trackNumber);

    // Close the ISO file
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

    LLVMFuzzerTestOneInput_167(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
