#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static void setup_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_52(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3 + 4) return 0;

    setup_dummy_file(Data, Size);

    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    u32 trackNumber = *(u32 *)Data;
    Data += sizeof(u32);
    Size -= sizeof(u32);

    u32 sampleDescriptionIndex = *(u32 *)Data;
    Data += sizeof(u32);
    Size -= sizeof(u32);

    u32 Index = *(u32 *)Data;
    Data += sizeof(u32);
    Size -= sizeof(u32);

    char *xmlnamespace = (char *)Data;
    char *schema_loc = (char *)Data;
    char *content_encoding = (char *)Data;
    char *URLname = (char *)Data;
    char *URNname = (char *)Data;

    u32 outDescriptionIndex = 0;
    char *lang = NULL;
    const char *mime = NULL;
    const char *encoding = NULL;
    const char *config = NULL;
    const char *threeCharCodes = NULL;
    const char *notice = NULL;
    const char *xml_schema_loc = NULL;
    const char *mimes = NULL;

    GF_VPConfig *cfg = (GF_VPConfig *)malloc(sizeof(GF_VPConfig));
    if (!cfg) {
        gf_isom_close(isom_file);
        return 0;
    }

    u32 vpx_type = 'vp08';

    // Test gf_isom_new_xml_metadata_description
    gf_isom_new_xml_metadata_description(isom_file, trackNumber, xmlnamespace, schema_loc, content_encoding, &outDescriptionIndex);

    // Test gf_isom_get_media_language
    gf_isom_get_media_language(isom_file, trackNumber, &lang);
    if (lang) free(lang);

    // Test gf_isom_stxt_get_description
    gf_isom_stxt_get_description(isom_file, trackNumber, sampleDescriptionIndex, &mime, &encoding, &config);

    // Test gf_isom_get_copyright
    gf_isom_get_copyright(isom_file, Index, &threeCharCodes, &notice);

    // Test gf_isom_vp_config_new
    gf_isom_vp_config_new(isom_file, trackNumber, cfg, URLname, URNname, &outDescriptionIndex, vpx_type);

    // Test gf_isom_xml_subtitle_get_description
    gf_isom_xml_subtitle_get_description(isom_file, trackNumber, sampleDescriptionIndex, &xmlnamespace, &xml_schema_loc, &mimes);

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

    LLVMFuzzerTestOneInput_52(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
