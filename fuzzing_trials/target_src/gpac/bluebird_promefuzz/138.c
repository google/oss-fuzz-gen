#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "/src/gpac/include/gpac/isomedia.h"

static void cleanup_iso_file(GF_ISOFile *iso_file) {
    if (!iso_file) return;
    gf_isom_close(iso_file);
}

static GF_ISOFile *initialize_iso_file(const uint8_t *Data, size_t Size) {
    // Write input data to a dummy file
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return NULL;
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Open the dummy file as an ISO file
    GF_ISOFile *iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return iso_file;
}

int LLVMFuzzerTestOneInput_138(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0; // Ensure enough data for operations

    GF_ISOFile *iso_file = initialize_iso_file(Data, Size);
    if (!iso_file) return 0;

    u32 trackNumber = Data[0];
    u32 matrix[9];
    u32 timeScale = Data[1];
    u32 sampleDescriptionIndex = Data[2];
    GF_MasteringDisplayColourVolumeInfo *mdcv = NULL;
    GF_ContentLightLevelInfo *clli = NULL;

    // Fuzz gf_isom_get_track_matrix
    gf_isom_get_track_matrix(iso_file, trackNumber, matrix);

    // Fuzz gf_isom_update_edit_list_duration
    gf_isom_update_edit_list_duration(iso_file, trackNumber);

    // Fuzz gf_isom_set_timescale
    gf_isom_set_timescale(iso_file, timeScale);

    // Fuzz gf_isom_get_chunks_infos
    u32 dur_min, dur_avg, dur_max, size_min, size_avg, size_max;
    gf_isom_get_chunks_infos(iso_file, trackNumber, &dur_min, &dur_avg, &dur_max, &size_min, &size_avg, &size_max);

    // Fuzz gf_isom_set_high_dynamic_range_info
    gf_isom_set_high_dynamic_range_info(iso_file, trackNumber, sampleDescriptionIndex, mdcv, clli);

    // Fuzz gf_isom_purge_track_reference
    gf_isom_purge_track_reference(iso_file, trackNumber);

    cleanup_iso_file(iso_file);
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

    LLVMFuzzerTestOneInput_138(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
