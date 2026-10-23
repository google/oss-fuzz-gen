#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> // Include for strdup
#include <gpac/isomedia.h> // Assuming this is the correct header for GF_ISOFile

int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;

    // Ensure the data is null-terminated before passing it to gf_isom_open
    // Allocate a new buffer with an extra byte for the null terminator
    char *null_terminated_data = (char *)malloc(size + 1);
    if (!null_terminated_data) {
        return 0; // If memory allocation fails, return early
    }

    // Copy the data into the new buffer and null-terminate it
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Initialize the movie with some non-NULL value
    movie = gf_isom_open(null_terminated_data, GF_ISOM_OPEN_READ, NULL);

    // Free the null-terminated buffer as it's no longer needed
    free(null_terminated_data);

    if (movie == NULL) {
        // If gf_isom_open fails, we can't proceed, so return early
        return 0;
    }

    // Call the function-under-test
    gf_isom_reset_sample_count(movie);

    // Clean up resources
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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
