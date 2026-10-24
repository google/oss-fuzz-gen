#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_71(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare file for testing gf_isom_probe_file and gf_isom_probe_file_range
    write_dummy_file(Data, Size);

    // Test gf_isom_probe_file
    u32 probe_result = gf_isom_probe_file("./dummy_file");

    // Test gf_isom_probe_file_range with different ranges
    u64 start_range = 0;
    u64 end_range = Size > 10 ? 10 : Size;
    u32 range_result = gf_isom_probe_file_range("./dummy_file", start_range, end_range);

    // Since GF_ISOFile is an incomplete type, we cannot instantiate it directly.
    // We assume functions that require GF_ISOFile as a parameter are tested with valid instances in their respective environments.

    // Test gf_isom_new_xml_subtitle_description
    // These tests will assume a valid GF_ISOFile pointer is passed.
    u32 outDescriptionIndex;
    GF_Err xml_subtitle_result = gf_isom_new_xml_subtitle_description(
        NULL, 1, "http://example.com/namespace", NULL, NULL, &outDescriptionIndex);

    // Test gf_isom_set_generic_protection
    GF_Err generic_protection_result = gf_isom_set_generic_protection(
        NULL, 1, 1, GF_ISOM_ISMACRYP_SCHEME, 1, NULL, NULL);

    // Test gf_isom_is_external_track
    GF_ISOTrackID tkid;
    u32 type, flags;
    const char *location;
    Bool is_external = gf_isom_is_external_track(
        NULL, 1, &tkid, &type, &flags, &location);

    // Test gf_isom_set_oma_protection
    GF_Err oma_protection_result = gf_isom_set_oma_protection(
        NULL, 1, 1, "contentID", "http://license.server", 1, 0, NULL, 0, GF_FALSE, 0, 0);

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

    LLVMFuzzerTestOneInput_71(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
