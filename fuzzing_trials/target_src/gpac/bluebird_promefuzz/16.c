#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

// Dummy file path
#define DUMMY_FILE_PATH "./dummy_file"

// Fuzzing entry point
int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare a dummy GF_ISOFile object
    GF_ISOFile *isom_file = NULL; // Assuming GF_ISOFile can be NULL for testing

    // Prepare a dummy GF_ISMASample object
    GF_ISMASample *sample = gf_isom_ismacryp_new_sample();
    if (!sample) {
        return 0;
    }

    // Test gf_isom_ismacryp_delete_sample
    sample->dataLength = 0; // Set dataLength to 0 to retain buffer
    gf_isom_ismacryp_delete_sample(sample);

    // Test gf_isom_set_ismacryp_protection
    char scheme_uri[] = "scheme_uri";
    char kms_URI[] = "kms_URI";
    gf_isom_set_ismacryp_protection(isom_file, 1, 1, 'iAEC', 1, scheme_uri, kms_URI, GF_TRUE, 16, 16);

    // Test gf_isom_is_ismacryp_media
    gf_isom_is_ismacryp_media(isom_file, 1, 1);

    // Test gf_isom_get_ismacryp_sample
    GF_ISOSample *iso_sample = (GF_ISOSample *) malloc(sizeof(GF_ISOSample));
    if (iso_sample) {
        gf_isom_get_ismacryp_sample(isom_file, 1, iso_sample, 1);
        free(iso_sample);
    }

    // Write data to a dummy file for gf_isom_ismacryp_sample_from_data
    FILE *dummy_file = fopen(DUMMY_FILE_PATH, "wb");
    if (dummy_file) {
        fwrite(Data, 1, Size, dummy_file);
        fclose(dummy_file);
    }

    // Test gf_isom_ismacryp_sample_from_data using the dummy file data
    GF_ISMASample *new_sample = gf_isom_ismacryp_sample_from_data((u8 *)Data, (u32)Size, GF_TRUE, 16, 16);
    if (new_sample) {
        gf_isom_ismacryp_delete_sample(new_sample);
    }

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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
