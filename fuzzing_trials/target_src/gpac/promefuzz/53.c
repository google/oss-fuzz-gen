// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_get_stsd_template at isom_write.c:4310:8 in isomedia.h
// gf_isom_get_user_data at isom_read.c:2769:8 in isomedia.h
// gf_isom_update_sample_description_from_template at isom_write.c:8597:8 in isomedia.h
// gf_isom_flac_config_get at sample_descs.c:386:8 in isomedia.h
// gf_isom_remove_track_reference at isom_write.c:5051:8 in isomedia.h
// gf_isom_piff_allocate_storage at drm_sample.c:1155:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_53(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 4 + sizeof(bin128)) return 0;

    GF_ISOFile *isom_file = NULL;
    u32 trackNumber = *((u32 *)(Data));
    u32 sampleDescriptionIndex = *((u32 *)(Data + sizeof(u32)));
    u32 UserDataType = *((u32 *)(Data + sizeof(u32) * 2));
    bin128 UUID;
    memcpy(UUID, Data + sizeof(u32) * 3, sizeof(bin128));
    u32 UserDataIndex = 1;

    // Prepare output buffers
    u8 *output = NULL;
    u32 output_size = 0;
    u8 *userData = NULL;
    u32 userDataSize = 0;
    u8 *dsi = NULL;
    u32 dsi_size = 0;

    // Fuzz gf_isom_get_stsd_template
    gf_isom_get_stsd_template(isom_file, trackNumber, sampleDescriptionIndex, &output, &output_size);
    if (output) free(output);

    // Fuzz gf_isom_get_user_data
    gf_isom_get_user_data(isom_file, trackNumber, UserDataType, UUID, UserDataIndex, &userData, &userDataSize);
    if (userData) free(userData);

    // Fuzz gf_isom_update_sample_description_from_template
    gf_isom_update_sample_description_from_template(isom_file, trackNumber, sampleDescriptionIndex, (u8 *)Data, (u32)Size);

    // Fuzz gf_isom_flac_config_get
    gf_isom_flac_config_get(isom_file, trackNumber, sampleDescriptionIndex, &dsi, &dsi_size);
    if (dsi) free(dsi);

    // Fuzz gf_isom_remove_track_reference
    gf_isom_remove_track_reference(isom_file, trackNumber, UserDataType);

    // Fuzz gf_isom_piff_allocate_storage
    gf_isom_piff_allocate_storage(isom_file, trackNumber, 0, 0, UUID);

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
    