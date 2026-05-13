#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

#define DUMMY_FILE "./dummy_file"

static GF_ISOFile* create_dummy_isofile() {
    // Assuming we have a function to create or open an ISO file in the actual library.
    // Since the third parameter is a temporary directory, we can pass NULL.
    GF_ISOFile* isom_file = gf_isom_open(DUMMY_FILE, GF_ISOM_OPEN_READ, NULL);
    return isom_file;
}

static GF_AC4Config* create_dummy_ac4_config() {
    GF_AC4Config* cfg = (GF_AC4Config*)malloc(sizeof(GF_AC4Config));
    if (cfg) {
        memset(cfg, 0, sizeof(GF_AC4Config));
    }
    return cfg;
}

int LLVMFuzzerTestOneInput_97(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32)) return 0;

    GF_ISOFile* isom_file = create_dummy_isofile();
    if (!isom_file) return 0;

    FILE* file = fopen(DUMMY_FILE, "wb");
    if (!file) {
        gf_isom_close(isom_file);
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    u32 trackNumber = Data[0] % 10;
    u32 padding_bytes = Data[1] % 256;
    u32 sampleDescriptionIndex = Data[2] % 10;
    u32 BrandIndex = Data[3] % 10;
    u32 brand;
    u32 outOriginalFormat;

    GF_AC4Config* cfg = create_dummy_ac4_config();
    if (!cfg) {
        gf_isom_close(isom_file);
        return 0;
    }

    gf_isom_set_sample_padding(isom_file, trackNumber, padding_bytes);
    gf_isom_refresh_size_info(isom_file, trackNumber);
    gf_isom_ac4_config_update(isom_file, trackNumber, sampleDescriptionIndex, cfg);
    gf_isom_get_alternate_brand(isom_file, BrandIndex, &brand);
    gf_isom_get_original_format_type(isom_file, trackNumber, sampleDescriptionIndex, &outOriginalFormat);
    gf_isom_set_inplace_padding(isom_file, padding_bytes);

    free(cfg);
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

    LLVMFuzzerTestOneInput_97(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
