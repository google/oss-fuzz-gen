// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_new_webvtt_description at sample_descs.c:1637:8 in isomedia.h
// gf_isom_remove_track_kind at isom_write.c:3185:8 in isomedia.h
// gf_isom_subtitle_set_mime at sample_descs.c:1294:8 in isomedia.h
// gf_isom_new_generic_sample_description at isom_write.c:4701:8 in isomedia.h
// gf_isom_get_ismacryp_info at drm_sample.c:257:8 in isomedia.h
// gf_isom_get_xml_metadata_description at sample_descs.c:1166:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_isofile() {
    // Allocate a dummy GF_ISOFile using a mock size, since we don't have the full definition
    GF_ISOFile* iso_file = (GF_ISOFile*)malloc(1024);
    if (!iso_file) return NULL;
    memset(iso_file, 0, 1024);
    return iso_file;
}

int LLVMFuzzerTestOneInput_229(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0;

    GF_ISOFile* isom_file = create_dummy_isofile();
    if (!isom_file) return 0;

    u32 trackNumber = Data[0];
    const char *URLname = (Size > 1) ? (const char*)&Data[1] : NULL;
    const char *URNname = (Size > 2) ? (const char*)&Data[2] : NULL;
    u32 outDescriptionIndex;
    const char *config = (Size > 3) ? (const char*)&Data[3] : NULL;

    gf_isom_new_webvtt_description(isom_file, trackNumber, URLname, URNname, &outDescriptionIndex, config);

    gf_isom_remove_track_kind(isom_file, trackNumber, URLname, URNname);

    u32 sampleDescriptionIndex = Data[0];
    gf_isom_subtitle_set_mime(isom_file, trackNumber, sampleDescriptionIndex, config);

    GF_GenericSampleDescription udesc;
    memset(&udesc, 0, sizeof(GF_GenericSampleDescription));
    gf_isom_new_generic_sample_description(isom_file, trackNumber, URLname, URNname, &udesc, &outDescriptionIndex);

    u32 outOriginalFormat, outSchemeType, outSchemeVersion;
    const char *outSchemeURI, *outKMS_URI;
    Bool outSelectiveEncryption;
    u32 outIVLength, outKeyIndicationLength;
    gf_isom_get_ismacryp_info(isom_file, trackNumber, sampleDescriptionIndex, &outOriginalFormat, &outSchemeType, &outSchemeVersion, &outSchemeURI, &outKMS_URI, &outSelectiveEncryption, &outIVLength, &outKeyIndicationLength);

    const char *xmlnamespace, *schema_loc, *content_encoding;
    gf_isom_get_xml_metadata_description(isom_file, trackNumber, sampleDescriptionIndex, &xmlnamespace, &schema_loc, &content_encoding);

    free(isom_file);
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

        LLVMFuzzerTestOneInput_229(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    