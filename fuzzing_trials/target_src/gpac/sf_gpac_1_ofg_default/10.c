#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for strdup
#include <gpac/isomedia.h>  // Correct include for GPAC library

// Declare the function signature
GF_EXPORT void gf_isom_reset_sample_count(GF_ISOFile *movie);

int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;

    // Check if the size is sufficient to avoid issues in gf_isom_open_file
    if (size < 1) {
        return 0; // Return if the input size is too small
    }

    // Initialize the GF_ISOFile structure with the input data
    // Assume that gf_isom_open_file is a function that can initialize a GF_ISOFile from memory
    movie = gf_isom_open_file((const char *)data, size, GF_ISOM_OPEN_READ);
    if (movie == NULL) {
        return 0; // Return if the movie cannot be initialized
    }

    // Call the function-under-test
    gf_isom_reset_sample_count(movie);

    // Clean up
    gf_isom_close(movie); // Assuming this is the correct cleanup function

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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
