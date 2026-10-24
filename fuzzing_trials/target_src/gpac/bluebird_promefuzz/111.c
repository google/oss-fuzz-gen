#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Create a dummy GF_ISOFile structure
    GF_ISOFile *iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ_DUMP, NULL);
    return iso_file;
}

static void free_dummy_iso_file(GF_ISOFile *iso_file) {
    if (iso_file) {
        gf_isom_close(iso_file);
    }
}

int LLVMFuzzerTestOneInput_111(const uint8_t *Data, size_t Size) {
    GF_ISOFile *iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    u32 trackNumber = Size > 0 ? Data[0] : 0;
    u32 sampleDescriptionIndex = Size > 1 ? Data[1] : 0;
    u32 scheme_type = Size > 2 ? Data[2] : 0;
    u32 scheme_version = Size > 3 ? Data[3] : 0;
    char *scheme_uri = (char *)Data + 4;
    char *kms_URI = (char *)Data + 5;
    Bool selective_encryption = Size > 6 ? Data[6] : 0;
    u32 KI_length = Size > 7 ? Data[7] : 0;
    u32 IV_length = Size > 8 ? Data[8] : 0;

    gf_isom_set_ismacryp_protection(iso_file, trackNumber, sampleDescriptionIndex, scheme_type,
                                    scheme_version, scheme_uri, kms_URI, selective_encryption, KI_length, IV_length);

    u32 outOriginalFormat, outSchemeType, outSchemeVersion;
    const char *outMetadata;
    gf_isom_get_adobe_protection_info(iso_file, trackNumber, sampleDescriptionIndex, &outOriginalFormat, &outSchemeType, &outSchemeVersion, &outMetadata);

    Bool is_selective_enc = Size > 9 ? Data[9] : 0;
    char *metadata = (char *)Data + 10;
    u32 len = Size > 10 ? Data[10] : 0;
    gf_isom_set_adobe_protection(iso_file, trackNumber, sampleDescriptionIndex, scheme_type, scheme_version, is_selective_enc, metadata, len);

    const char *outSchemeURI, *outKMS_URI;
    Bool outSelectiveEncryption;
    u32 outIVLength, outKeyIndicationLength;
    gf_isom_get_ismacryp_info(iso_file, trackNumber, sampleDescriptionIndex, &outOriginalFormat, &outSchemeType, &outSchemeVersion, &outSchemeURI, &outKMS_URI, &outSelectiveEncryption, &outIVLength, &outKeyIndicationLength);

    const char *outContentID, *outRightsIssuerURL, *outTextualHeaders;
    u32 outTextualHeadersLen, outEncryptionType;
    u64 outPlaintextLength;
    gf_isom_get_omadrm_info(iso_file, trackNumber, sampleDescriptionIndex, &outOriginalFormat, &outSchemeType, &outSchemeVersion, &outContentID, &outRightsIssuerURL, &outTextualHeaders, &outTextualHeadersLen, &outPlaintextLength, &outEncryptionType, &outSelectiveEncryption, &outIVLength, &outKeyIndicationLength);

    char *contentID = (char *)Data + 11;
    char *kms_URI_protection = (char *)Data + 12;
    u32 encryption_type = Size > 13 ? Data[13] : 0;
    u64 plainTextLength = Size > 14 ? Data[14] : 0;
    char *textual_headers = (char *)Data + 15;
    u32 textual_headers_len = Size > 15 ? Data[15] : 0;
    Bool selective_encryption_protection = Size > 16 ? Data[16] : 0;
    u32 KI_length_protection = Size > 17 ? Data[17] : 0;
    u32 IV_length_protection = Size > 18 ? Data[18] : 0;

    gf_isom_set_oma_protection(iso_file, trackNumber, sampleDescriptionIndex,
                               contentID, kms_URI_protection, encryption_type, plainTextLength, textual_headers, textual_headers_len,
                               selective_encryption_protection, KI_length_protection, IV_length_protection);

    free_dummy_iso_file(iso_file);
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

    LLVMFuzzerTestOneInput_111(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
