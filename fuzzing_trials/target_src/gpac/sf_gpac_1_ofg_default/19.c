#include <stdint.h>
#include <stddef.h>
#include <gpac/isomedia.h>
#include <gpac/internal/isomedia_dev.h> // Ensure this is the correct header for the functions used

int LLVMFuzzerTestOneInput_19(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;

    // Ensure that the data is non-null and has a minimum size
    if (data == NULL || size < 1) {
        return 0;
    }

    // Create a new ISOFile instance
    movie = gf_isom_open_file("dummy.mp4", GF_ISOM_OPEN_READ, NULL); // Use an appropriate function
    if (movie == NULL) {
        return 0;
    }

    // Call the function-under-test
    gf_isom_reset_sample_count(movie); // This function returns void, so no need to assign

    // Close the ISOFile instance
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

    LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
