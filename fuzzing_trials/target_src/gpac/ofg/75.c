#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for strdup
#include <gpac/isomedia.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_75(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated before using it as a string
    char *data_copy = (char *)malloc(size + 1);
    if (!data_copy) {
        return 0; // Exit if memory allocation fails
    }
    memcpy(data_copy, data, size);
    data_copy[size] = '\0'; // Null-terminate the string

    // Declare and initialize variables
    GF_ISOFile *movie = gf_isom_open(data_copy, GF_ISOM_OPEN_READ, NULL);
    u32 trackNumber = 1; // Assuming track number 1 for testing
    u32 duration = size > 0 ? (u32)(data[0]) : 1; // Use the first byte of data for duration or default to 1

    // Check if movie is successfully opened
    if (movie != NULL) {
        // Call the function-under-test
        gf_isom_set_last_sample_duration(movie, trackNumber, duration);

        // Close the movie file
        gf_isom_close(movie);
    }

    free(data_copy); // Free the allocated memory

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_75(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
