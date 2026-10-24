#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static void initialize_iso_file(GF_ISOFile **isom_file) {
    *isom_file = NULL; // Set to NULL as we can't allocate an incomplete type
}

static void cleanup_iso_file(GF_ISOFile *isom_file) {
    // No cleanup needed for incomplete type
}

int LLVMFuzzerTestOneInput_147(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    GF_ISOFile *isom_file;
    initialize_iso_file(&isom_file);

    // Test gf_isom_set_media_language
    if (Size >= 4) {
        u32 trackNumber = Data[0];
        char code[4];
        memcpy(code, &Data[1], 3);
        code[3] = '\0';
        gf_isom_set_media_language(isom_file, trackNumber, code);
    }

    // Test gf_isom_get_copyright
    if (Size >= 5) {
        u32 index = Data[4];
        const char *threeCharCodes = NULL;
        const char *notice = NULL;
        gf_isom_get_copyright(isom_file, index, &threeCharCodes, &notice);
    }

    // Test gf_isom_new_mpha_description
    if (Size >= 10) {
        u32 trackNumber = Data[5];
        u32 outDescriptionIndex;
        u8 dsi[4];
        memcpy(dsi, &Data[6], 4);
        u32 dsi_size = 4;
        u32 mha_subtype = Data[9];
        gf_isom_new_mpha_description(isom_file, trackNumber, NULL, NULL, &outDescriptionIndex, dsi, dsi_size, mha_subtype);
    }

    // Test gf_isom_set_handler_name
    if (Size >= 11) {
        u32 trackNumber = Data[10];
        gf_isom_set_handler_name(isom_file, trackNumber, "handler_name");
    }

    // Test gf_isom_new_mj2k_description
    if (Size >= 16) {
        u32 trackNumber = Data[11];
        u32 outDescriptionIndex;
        u8 dsi[4];
        memcpy(dsi, &Data[12], 4);
        u32 dsi_len = 4;
        gf_isom_new_mj2k_description(isom_file, trackNumber, NULL, NULL, &outDescriptionIndex, dsi, dsi_len);
    }

    // Test gf_isom_new_mpeg4_description
    if (Size >= 21) {
        u32 trackNumber = Data[16];
        GF_ESD esd;
        memset(&esd, 0, sizeof(GF_ESD));
        u32 outDescriptionIndex;
        gf_isom_new_mpeg4_description(isom_file, trackNumber, &esd, NULL, NULL, &outDescriptionIndex);
    }

    cleanup_iso_file(isom_file);
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

    LLVMFuzzerTestOneInput_147(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
