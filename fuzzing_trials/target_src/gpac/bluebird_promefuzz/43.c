#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static void initialize_dummy_file() {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        const char *dummy_data = "dummy data";
        fwrite(dummy_data, 1, strlen(dummy_data), file);
        fclose(file);
    }
}

static GF_ISOFile* create_dummy_iso_file() {
    return gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
}

static void cleanup_iso_file(GF_ISOFile *iso_file) {
    if (iso_file) {
        gf_isom_close(iso_file);
    }
}

int LLVMFuzzerTestOneInput_43(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3) return 0;

    initialize_dummy_file();
    GF_ISOFile *iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    u32 trackNumber = *(u32*)Data;
    u32 sampleDescriptionIndex = *(u32*)(Data + sizeof(u32));
    u32 scheme_type = *(u32*)(Data + sizeof(u32) * 2);
    u32 scheme_version = (Size >= sizeof(u32) * 4) ? *(u32*)(Data + sizeof(u32) * 3) : 1;
    char *scheme_uri = (Size >= sizeof(u32) * 5) ? (char*)(Data + sizeof(u32) * 4) : NULL;
    char *kms_URI = (Size >= sizeof(u32) * 6) ? (char*)(Data + sizeof(u32) * 5) : NULL;

    gf_isom_set_generic_protection(iso_file, trackNumber, sampleDescriptionIndex, scheme_type, scheme_version, scheme_uri, kms_URI);

    u32 outDescriptionIndex;
    char *URLname = (Size >= sizeof(u32) * 7) ? (char*)(Data + sizeof(u32) * 6) : NULL;
    char *URNname = (Size >= sizeof(u32) * 8) ? (char*)(Data + sizeof(u32) * 7) : NULL;
    char *config = (Size >= sizeof(u32) * 9) ? (char*)(Data + sizeof(u32) * 8) : NULL;

    gf_isom_new_webvtt_description(iso_file, trackNumber, URLname, URNname, &outDescriptionIndex, config);

    char *full_mime = (Size >= sizeof(u32) * 10) ? (char*)(Data + sizeof(u32) * 9) : NULL;
    gf_isom_subtitle_set_mime(iso_file, trackNumber, sampleDescriptionIndex, full_mime);

    GF_AC4Config ac4_config;
    memset(&ac4_config, 0, sizeof(GF_AC4Config));
    gf_isom_ac4_config_new(iso_file, trackNumber, &ac4_config, URLname, URNname, &outDescriptionIndex);

    char *new_scheme_uri = (Size >= sizeof(u32) * 11) ? (char*)(Data + sizeof(u32) * 10) : NULL;
    char *new_kms_uri = (Size >= sizeof(u32) * 12) ? (char*)(Data + sizeof(u32) * 11) : NULL;
    gf_isom_change_ismacryp_protection(iso_file, trackNumber, sampleDescriptionIndex, new_scheme_uri, new_kms_uri);

    char *contentID = (Size >= sizeof(u32) * 13) ? (char*)(Data + sizeof(u32) * 12) : NULL;
    u32 encryption_type = (Size >= sizeof(u32) * 14) ? *(u32*)(Data + sizeof(u32) * 13) : 0;
    u64 plainTextLength = (Size >= sizeof(u32) * 15) ? *(u64*)(Data + sizeof(u32) * 14) : 0;
    char *textual_headers = (Size >= sizeof(u32) * 16) ? (char*)(Data + sizeof(u32) * 15) : NULL;
    u32 textual_headers_len = (Size >= sizeof(u32) * 17) ? *(u32*)(Data + sizeof(u32) * 16) : 0;
    Bool selective_encryption = (Size >= sizeof(u32) * 18) ? *(Bool*)(Data + sizeof(u32) * 17) : 0;
    u32 KI_length = (Size >= sizeof(u32) * 19) ? *(u32*)(Data + sizeof(u32) * 18) : 0;
    u32 IV_length = (Size >= sizeof(u32) * 20) ? *(u32*)(Data + sizeof(u32) * 19) : 0;

    gf_isom_set_oma_protection(iso_file, trackNumber, sampleDescriptionIndex, contentID, kms_URI, encryption_type, plainTextLength, textual_headers, textual_headers_len, selective_encryption, KI_length, IV_length);

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

    LLVMFuzzerTestOneInput_43(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
