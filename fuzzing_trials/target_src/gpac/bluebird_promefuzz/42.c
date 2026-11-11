#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile *create_dummy_iso_file() {
    // Open a dummy file to simulate the ISO file
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return NULL;
    fclose(file);

    // Use the API to open the ISO file instead of manually allocating it
    GF_ISOFile *iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return iso_file;
}

static GF_HEVCConfig *initialize_hevc_config(const uint8_t *Data, size_t Size) {
    GF_HEVCConfig *config = (GF_HEVCConfig *)malloc(sizeof(GF_HEVCConfig));
    if (config) {
        memset(config, 0, sizeof(GF_HEVCConfig));
        // Initialize config with some data if needed
    }
    return config;
}

int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size) {
    GF_ISOFile *iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    GF_HEVCConfig *hevc_config = initialize_hevc_config(Data, Size);
    if (!hevc_config) {
        gf_isom_close(iso_file);
        return 0;
    }

    u32 trackNumber = 1;
    u32 sampleDescriptionIndex = 1;
    Bool is_base_track = GF_FALSE;
    u32 outDescriptionIndex;
    GF_ISOMLHEVCTrackType track_type = 0; // Assuming some default value

    // Fuzz gf_isom_hevc_set_tile_config
    gf_isom_hevc_set_tile_config(iso_file, trackNumber, sampleDescriptionIndex, hevc_config, is_base_track);

    // Fuzz gf_isom_hevc_config_new
    gf_isom_hevc_config_new(iso_file, trackNumber, hevc_config, NULL, NULL, &outDescriptionIndex);

    // Fuzz gf_isom_lhvc_config_get
    GF_HEVCConfig *lhvc_config = gf_isom_lhvc_config_get(iso_file, trackNumber, sampleDescriptionIndex);
    if (lhvc_config) {
        free(lhvc_config);
    }

    // Fuzz gf_isom_lhvc_config_update
    gf_isom_lhvc_config_update(iso_file, trackNumber, sampleDescriptionIndex, hevc_config, track_type);

    // Fuzz gf_isom_hevc_config_update
    gf_isom_hevc_config_update(iso_file, trackNumber, sampleDescriptionIndex, hevc_config);

    // Fuzz gf_isom_hevc_config_get
    GF_HEVCConfig *hevc_config_get = gf_isom_hevc_config_get(iso_file, trackNumber, sampleDescriptionIndex);
    if (hevc_config_get) {
        free(hevc_config_get);
    }

    free(hevc_config);
    gf_isom_close(iso_file);

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

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
