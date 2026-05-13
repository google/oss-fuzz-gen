#include <stdint.h>
#include <stddef.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_64(const uint8_t *data, size_t size) {
    GF_ISOFile *movie;
    u32 trackNumber;
    u8 *stsd_data;
    u32 stsd_data_size;

    // Initialize movie
    movie = gf_isom_open("/tmp/fuzzfile.mp4", GF_ISOM_OPEN_READ, NULL);
    if (movie == NULL) {
        return 0;
    }

    // Set trackNumber to a non-zero value
    trackNumber = 1;

    // Ensure stsd_data is not NULL and has some data
    if (size > 0) {
        stsd_data = (u8 *)data;
        stsd_data_size = (u32)size;
    } else {
        stsd_data = (u8 *)"default";
        stsd_data_size = 7;
    }

    // Call the function-under-test
    gf_isom_set_track_stsd_templates(movie, trackNumber, stsd_data, stsd_data_size);

    // Clean up
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

    LLVMFuzzerTestOneInput_64(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
