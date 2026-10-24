// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_set_ipod_compatible at isom_write.c:9114:8 in isomedia.h
// gf_isom_remove_stream_description at isom_write.c:970:8 in isomedia.h
// gf_isom_lhvc_force_inband_config at avc_ext.c:2330:8 in isomedia.h
// gf_isom_get_visual_info at isom_read.c:3821:8 in isomedia.h
// gf_isom_set_mpegh_compatible_profiles at isom_write.c:9455:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* open_iso_file(const char *filename) {
    // Simulate opening an ISO file
    GF_ISOFile *file = gf_isom_open(filename, GF_ISOM_OPEN_EDIT, NULL);
    return file;
}

int LLVMFuzzerTestOneInput_63(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3) return 0; // Ensure enough data for function parameters

    // Create a dummy file for testing
    FILE *dummy_file = fopen("./dummy_file", "wb");
    if (!dummy_file) return 0;
    fwrite(Data, 1, Size, dummy_file);
    fclose(dummy_file);

    GF_ISOFile *isom_file = open_iso_file("./dummy_file");
    if (!isom_file) return 0;

    u32 trackNumber = *(u32 *)Data;
    u32 sampleDescriptionIndex = *(u32 *)(Data + sizeof(u32));
    u32 nb_compatible_profiles = *(u32 *)(Data + sizeof(u32) * 2);

    // Fuzz gf_isom_set_ipod_compatible
    gf_isom_set_ipod_compatible(isom_file, trackNumber);

    // Fuzz gf_isom_remove_stream_description
    gf_isom_remove_stream_description(isom_file, trackNumber, sampleDescriptionIndex);

    // Fuzz gf_isom_lhvc_force_inband_config
    gf_isom_lhvc_force_inband_config(isom_file, trackNumber, sampleDescriptionIndex);

    // Fuzz gf_isom_get_visual_info
    u32 Width = 0, Height = 0;
    gf_isom_get_visual_info(isom_file, trackNumber, sampleDescriptionIndex, &Width, &Height);

    // Fuzz gf_isom_set_mpegh_compatible_profiles
    u32 *profiles = NULL;
    if (nb_compatible_profiles > 0 && Size >= sizeof(u32) * (3 + nb_compatible_profiles)) {
        profiles = (u32 *)(Data + sizeof(u32) * 3);
    }
    gf_isom_set_mpegh_compatible_profiles(isom_file, trackNumber, sampleDescriptionIndex, profiles, nb_compatible_profiles);

    // Fuzz gf_isom_close
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

        LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    