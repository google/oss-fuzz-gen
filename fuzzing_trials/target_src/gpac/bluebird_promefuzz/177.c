#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Create a dummy ISO file object
    GF_ISOFile* iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return iso_file;
}

static GF_ISOSample* create_dummy_sample() {
    // Create a dummy sample object
    GF_ISOSample* sample = (GF_ISOSample*) malloc(sizeof(GF_ISOSample));
    if (!sample) return NULL;
    memset(sample, 0, sizeof(GF_ISOSample));
    return sample;
}

static void cleanup_iso_file(GF_ISOFile* iso_file) {
    if (iso_file) {
        gf_isom_close(iso_file);
    }
}

static void cleanup_sample(GF_ISOSample* sample) {
    if (sample) {
        free(sample);
    }
}

int LLVMFuzzerTestOneInput_177(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 2) return 0;

    GF_ISOFile *iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    u32 trackNumber = *((u32*)Data);
    u32 sampleNumber = *((u32*)(Data + sizeof(u32)));

    u32 sampleDescriptionIndex = 0;
    u64 data_offset = 0;

    GF_ISOSample *sample = create_dummy_sample();
    if (!sample) {
        cleanup_iso_file(iso_file);
        return 0;
    }

    // Fuzz gf_isom_get_sample
    GF_ISOSample *result_sample = gf_isom_get_sample(iso_file, trackNumber, sampleNumber, &sampleDescriptionIndex);
    if (result_sample) {
        gf_isom_sample_del(result_sample);
    }

    // Fuzz gf_isom_get_sample_ex
    result_sample = gf_isom_get_sample_ex(iso_file, trackNumber, sampleNumber, &sampleDescriptionIndex, sample, &data_offset);
    if (result_sample) {
        gf_isom_sample_del(result_sample);
    }

    // Fuzz gf_isom_get_sample_info
    result_sample = gf_isom_get_sample_info(iso_file, trackNumber, sampleNumber, &sampleDescriptionIndex, &data_offset);
    if (result_sample) {
        gf_isom_sample_del(result_sample);
    }

    // Fuzz gf_isom_add_sample_reference
    GF_Err err = gf_isom_add_sample_reference(iso_file, trackNumber, sampleDescriptionIndex, sample, data_offset);

    // Fuzz gf_isom_update_sample_reference
    err = gf_isom_update_sample_reference(iso_file, trackNumber, sampleNumber, sample, data_offset);

    // Fuzz gf_isom_get_sample_info_ex
    result_sample = gf_isom_get_sample_info_ex(iso_file, trackNumber, sampleNumber, &sampleDescriptionIndex, &data_offset, sample);
    if (result_sample) {
        gf_isom_sample_del(result_sample);
    }

    cleanup_sample(sample);
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

    LLVMFuzzerTestOneInput_177(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
