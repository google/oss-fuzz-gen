#include <stdint.h>
#include <stddef.h>
#include <gpac/isomedia.h>

// Define a sample GF_ISOFile structure for testing purposes
GF_ISOFile* create_sample_movie() {
    // Normally, you would initialize this with actual data
    // For fuzzing purposes, we assume a simple initialization
    GF_ISOFile *movie = gf_isom_open(NULL, GF_ISOM_OPEN_WRITE, NULL);
    return movie;
}

int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    // Create a sample movie object
    GF_ISOFile *movie = create_sample_movie();
    if (movie == NULL) {
        return 0;
    }

    // Ensure trackNumber is a valid value
    u32 trackNumber = 1; // Assuming track 1 for simplicity

    // Call the function-under-test with the provided data
    gf_isom_append_sample_data(movie, trackNumber, (u8 *)data, (u32)size);

    // Close the movie to clean up resources
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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
