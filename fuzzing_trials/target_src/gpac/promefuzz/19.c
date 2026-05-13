// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_svc_config_get at avc_ext.c:2572:15 in isomedia.h
// gf_isom_mvc_config_get at avc_ext.c:2589:15 in isomedia.h
// gf_isom_avc_config_get at avc_ext.c:2468:15 in isomedia.h
// gf_isom_mvc_config_update at avc_ext.c:1777:8 in isomedia.h
// gf_isom_svc_config_update at avc_ext.c:1771:8 in isomedia.h
// gf_isom_avc_config_update at avc_ext.c:1765:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Allocate and initialize a dummy ISO file structure
    GF_ISOFile *iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return iso_file;
}

static void cleanup_iso_file(GF_ISOFile *iso_file) {
    if (iso_file) {
        // Close the ISO file
        gf_isom_close(iso_file);
    }
}

int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3) return 0;

    GF_ISOFile *iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    u32 trackNumber = *((u32 *)Data);
    u32 sampleDescriptionIndex = *((u32 *)(Data + sizeof(u32)));
    Bool is_additional = (Bool)Data[2 * sizeof(u32)];

    // Fuzz gf_isom_svc_config_get
    GF_AVCConfig *svc_config = gf_isom_svc_config_get(iso_file, trackNumber, sampleDescriptionIndex);
    if (svc_config) {
        free(svc_config);
    }

    // Fuzz gf_isom_mvc_config_get
    GF_AVCConfig *mvc_config = gf_isom_mvc_config_get(iso_file, trackNumber, sampleDescriptionIndex);
    if (mvc_config) {
        free(mvc_config);
    }

    // Fuzz gf_isom_avc_config_get
    GF_AVCConfig *avc_config = gf_isom_avc_config_get(iso_file, trackNumber, sampleDescriptionIndex);
    if (avc_config) {
        free(avc_config);
    }

    // Create a dummy AVCConfig for update functions
    GF_AVCConfig *dummy_avc_config = (GF_AVCConfig *)malloc(sizeof(GF_AVCConfig));
    if (dummy_avc_config) {
        // Fuzz gf_isom_mvc_config_update
        gf_isom_mvc_config_update(iso_file, trackNumber, sampleDescriptionIndex, dummy_avc_config, is_additional);

        // Fuzz gf_isom_svc_config_update
        gf_isom_svc_config_update(iso_file, trackNumber, sampleDescriptionIndex, dummy_avc_config, is_additional);

        // Fuzz gf_isom_avc_config_update
        gf_isom_avc_config_update(iso_file, trackNumber, sampleDescriptionIndex, dummy_avc_config);

        free(dummy_avc_config);
    }

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

        LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    