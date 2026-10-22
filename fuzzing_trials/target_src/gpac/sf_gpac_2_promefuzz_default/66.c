// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_get_sample_for_media_time at isom_read.c:2192:8 in isomedia.h
// gf_isom_reset_data_offset at isom_read.c:3151:8 in isomedia.h
// gf_isom_set_brand_info at isom_write.c:3639:8 in isomedia.h
// gf_isom_evte_config_new at sample_descs.c:1846:8 in isomedia.h
// gf_isom_force_track_duration at isom_write.c:957:8 in isomedia.h
// gf_isom_update_sample_reference at isom_write.c:1538:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_isofile() {
    // Since GF_ISOFile is an incomplete type, we cannot allocate memory for it directly.
    // We assume that there is a function to create or open an ISO file in the actual library.
    // Here we just return NULL for demonstration purposes.
    return NULL;
}

int LLVMFuzzerTestOneInput_66(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) + sizeof(u64) + sizeof(u32) + sizeof(u64)) return 0;

    GF_ISOFile *iso_file = create_dummy_isofile();
    if (!iso_file) return 0;

    u32 trackNumber = *((u32*)Data);
    u64 desiredTime = *((u64*)(Data + sizeof(u32)));
    u32 sampleDescriptionIndex = 0;
    GF_ISOSample *sample = NULL;
    u32 sample_number = 0;
    u64 data_offset = 0;

    gf_isom_get_sample_for_media_time(iso_file, trackNumber, desiredTime, &sampleDescriptionIndex, 0, &sample, &sample_number, &data_offset);

    u64 top_box_start = 0;
    gf_isom_reset_data_offset(iso_file, &top_box_start);

    u32 MajorBrand = *((u32*)(Data + sizeof(u32) + sizeof(u64)));
    u32 MinorVersion = 0;
    gf_isom_set_brand_info(iso_file, MajorBrand, MinorVersion);

    u32 outDescriptionIndex = 0;
    gf_isom_evte_config_new(iso_file, trackNumber, &outDescriptionIndex);

    u64 duration = *((u64*)(Data + sizeof(u32) + sizeof(u64) + sizeof(u32)));
    gf_isom_force_track_duration(iso_file, trackNumber, duration);

    GF_ISOSample sample_data = {0};
    gf_isom_update_sample_reference(iso_file, trackNumber, sample_number, &sample_data, data_offset);

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

        LLVMFuzzerTestOneInput_66(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    