#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include string.h for memcpy
#include "/src/gpac/include/gpac/isomedia.h"

int LLVMFuzzerTestOneInput_145(const uint8_t *data, size_t size) {
    // Initialize variables
    GF_ISOFile *movie = gf_isom_open("temp.mp4", GF_ISOM_OPEN_WRITE, NULL);
    u32 trackNumber = 1;  // Assuming track number starts from 1
    u32 sampleNumber = 1; // Assuming sample number starts from 1
    GF_ISOSample *sample = gf_isom_sample_new();
    u64 data_offset = 0;

    // Check if movie and sample are initialized properly
    if (!movie || !sample) {
        if (movie) gf_isom_close(movie);
        if (sample) gf_isom_sample_del(&sample);
        return 0;
    }

    // Populate sample with some data from the input
    sample->dataLength = size < 1024 ? size : 1024; // Limit the data length
    sample->data = (char*)malloc(sample->dataLength);
    if (sample->data) {
        memcpy(sample->data, data, sample->dataLength);
    } else {
        gf_isom_close(movie);
        gf_isom_sample_del(&sample);
        return 0;
    }

    // Call the function under test
    gf_isom_update_sample_reference(movie, trackNumber, sampleNumber, sample, data_offset);

    // Clean up
    gf_isom_close(movie);
    gf_isom_sample_del(&sample);

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

    LLVMFuzzerTestOneInput_145(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
