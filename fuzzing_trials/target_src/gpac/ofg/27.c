#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = gf_isom_open("dummy.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (!movie) {
        return 0;
    }

    u32 trackNumber = 1; // Assuming at least one track exists
    u32 sampleNumber = 1; // Assuming at least one sample exists

    // Allocate and initialize a sample
    GF_ISOSample *sample = gf_isom_sample_new();
    if (!sample) {
        gf_isom_close(movie);
        return 0;
    }

    // Set sample data from fuzzing input
    sample->dataLength = size;
    sample->data = (char *)malloc(size);
    if (!sample->data) {
        gf_isom_sample_del(&sample);
        gf_isom_close(movie);
        return 0;
    }

    memcpy(sample->data, data, size);

    // Set other sample fields as needed
    sample->DTS = 0;
    sample->CTS_Offset = 0;
    sample->IsRAP = 1;

    Bool data_only = 0; // Set to false for full update

    // Call the function under test
    gf_isom_update_sample(movie, trackNumber, sampleNumber, sample, data_only);

    // Clean up
    free(sample->data);
    gf_isom_sample_del(&sample);
    gf_isom_close(movie);

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

    LLVMFuzzerTestOneInput_27(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
