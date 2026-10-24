#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    // Prepare dummy data for trackNumber and other parameters
    u32 trackNumber = 1;
    u32 matrix[9] = {0};
    u32 sample_number = 1;
    u32 grouping_type = 0;
    u32 grouping_type_parameter = 0;
    u32 sampleGroupDescIndex = 0;
    u32 hSpacing = 0;
    u32 vSpacing = 0;
    u32 MajorBrand = 0;
    u32 MinorVersion = 0;
    u32 dur_min = 0, dur_avg = 0, dur_max = 0;
    u32 size_min = 0, size_avg = 0, size_max = 0;
    u32 alternateGroupID = 0;
    u32 nb_groups = 0;

    // Write dummy file
    write_dummy_file(Data, Size);

    // Open the ISO file from the dummy file
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) {
        return 0;
    }

    // Invoke gf_isom_get_track_matrix
    gf_isom_get_track_matrix(isom_file, trackNumber, matrix);

    // Invoke gf_isom_get_sample_to_group_info
    gf_isom_get_sample_to_group_info(isom_file, trackNumber, sample_number, grouping_type, grouping_type_parameter, &sampleGroupDescIndex);

    // Invoke gf_isom_get_pixel_aspect_ratio
    gf_isom_get_pixel_aspect_ratio(isom_file, trackNumber, 1, &hSpacing, &vSpacing);

    // Invoke gf_isom_set_brand_info
    gf_isom_set_brand_info(isom_file, MajorBrand, MinorVersion);

    // Invoke gf_isom_get_chunks_infos
    gf_isom_get_chunks_infos(isom_file, trackNumber, &dur_min, &dur_avg, &dur_max, &size_min, &size_avg, &size_max);

    // Invoke gf_isom_get_track_switch_group_count
    gf_isom_get_track_switch_group_count(isom_file, trackNumber, &alternateGroupID, &nb_groups);

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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
