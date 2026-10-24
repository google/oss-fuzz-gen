#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* create_dummy_isofile() {
    // Assuming GF_ISOFile is properly created using a library function
    GF_ISOFile *file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    if (!file) return NULL;
    return file;
}

static void free_dummy_isofile(GF_ISOFile *file) {
    if (file) {
        gf_isom_close(file);
    }
}

int LLVMFuzzerTestOneInput_83(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32)) {
        return 0;
    }

    GF_ISOFile *isom_file = create_dummy_isofile();
    if (!isom_file) {
        return 0;
    }

    // Test gf_isom_set_next_moof_number
    u32 moof_number = *((u32 *)Data);
    gf_isom_set_next_moof_number(isom_file, moof_number);

    // Test gf_isom_vp_config_get
    if (Size >= 2 * sizeof(u32)) {
        u32 trackNumber = *((u32 *)(Data + sizeof(u32)));
        u32 sampleDescriptionIndex = *((u32 *)(Data + 2 * sizeof(u32)));
        GF_VPConfig *vp_config = gf_isom_vp_config_get(isom_file, trackNumber, sampleDescriptionIndex);
        if (vp_config) {
            // Free the VPConfig if it was allocated
            free(vp_config);
        }
    }

    // Test gf_isom_new_track
    if (Size >= 3 * sizeof(u32)) {
        u32 trackID = *((u32 *)(Data + 3 * sizeof(u32)));
        u32 MediaType = *((u32 *)(Data + 4 * sizeof(u32)));
        u32 TimeScale = *((u32 *)(Data + 5 * sizeof(u32)));
        gf_isom_new_track(isom_file, trackID, MediaType, TimeScale);
    }

    // Test gf_isom_segment_get_track_fragment_count
    if (Size >= 4 * sizeof(u32)) {
        u32 moof_index = *((u32 *)(Data + 6 * sizeof(u32)));
        gf_isom_segment_get_track_fragment_count(isom_file, moof_index);
    }

    // Test gf_isom_get_avg_sample_delta
    if (Size >= 5 * sizeof(u32)) {
        u32 trackNumber = *((u32 *)(Data + 7 * sizeof(u32)));
        gf_isom_get_avg_sample_delta(isom_file, trackNumber);
    }

    // Test gf_isom_get_track_group
    if (Size >= 6 * sizeof(u32)) {
        u32 trackNumber = *((u32 *)(Data + 8 * sizeof(u32)));
        u32 track_group_type = *((u32 *)(Data + 9 * sizeof(u32)));
        gf_isom_get_track_group(isom_file, trackNumber, track_group_type);
    }

    free_dummy_isofile(isom_file);
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

    LLVMFuzzerTestOneInput_83(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
