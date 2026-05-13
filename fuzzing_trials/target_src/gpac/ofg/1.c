#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    // Initialize variables
    GF_ISOFile *movie = gf_isom_open("dummy.mp4", GF_ISOM_OPEN_READ, NULL);
    if (!movie) {
        return 0; // Return if movie could not be opened
    }

    u32 trackNumber = 1; // Assuming a valid track number for fuzzing

    // Allocate and initialize GF_ISOSample
    GF_ISOSample *sample = gf_isom_sample_new();
    if (!sample) {
        gf_isom_close(movie);
        return 0; // Return if sample could not be created
    }

    // Set some sample fields with fuzz data
    sample->dataLength = size;
    sample->data = (char *)malloc(size);
    if (!sample->data) {
        gf_isom_sample_del(&sample);
        gf_isom_close(movie);
        return 0; // Return if memory allocation fails
    }
    memcpy(sample->data, data, size);

    // Call the function under test
    gf_isom_add_sample_shadow(movie, trackNumber, sample);

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

    LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
