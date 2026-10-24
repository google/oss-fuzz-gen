#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h> // Include the necessary header for GF_ISOFile and gf_isom_reset_sample_count

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;

    // Attempt to open the ISO file using a different method that exists
    movie = gf_isom_open(NULL, GF_ISOM_OPEN_READ, NULL);

    // Check if the movie was successfully opened
    if (movie != NULL) {
        // Call the function-under-test
        gf_isom_reset_sample_count(movie);

        // Close the movie to clean up resources
        gf_isom_close(movie);
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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
