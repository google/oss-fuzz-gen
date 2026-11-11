#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for strdup
#include <gpac/isomedia.h> // Include the necessary header for GF_ISOFile
#include <gpac/tools.h>    // Include the necessary header for u64

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated to prevent buffer overflow
    char *null_terminated_data = (char *)malloc(size + 1);
    if (!null_terminated_data) {
        return 0; // Exit if memory allocation fails
    }
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Declare and initialize the GF_ISOFile structure
    GF_ISOFile *movie = gf_isom_open(null_terminated_data, GF_ISOM_OPEN_READ, NULL);
    free(null_terminated_data); // Free the allocated memory for null-terminated data
    if (!movie) {
        return 0; // Exit if the movie cannot be opened
    }

    // Declare and initialize the u64 variable
    u64 top_box_start = 0;

    // Call the function-under-test
    gf_isom_reset_data_offset(movie, &top_box_start);

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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
