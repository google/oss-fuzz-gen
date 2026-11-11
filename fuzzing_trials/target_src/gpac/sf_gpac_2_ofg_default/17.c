#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <gpac/isomedia.h>  // Assuming the library provides this header for GF_ISOFile

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    GF_ISOFile *movie;
    u64 top_box_start;

    // Ensure the data is null-terminated to simulate a valid string input
    char *input_data = (char *)malloc(size + 1);
    if (!input_data) {
        return 0; // Exit if memory allocation fails
    }

    memcpy(input_data, data, size);
    input_data[size] = '\0'; // Null-terminate the input data

    // Initialize the GF_ISOFile structure
    movie = gf_isom_open(input_data, GF_ISOM_OPEN_READ, NULL);
    if (movie == NULL) {
        free(input_data); // Clean up allocated memory
        return 0; // If opening the file fails, exit early
    }

    // Initialize top_box_start with a non-zero value
    top_box_start = 1;

    // Call the function-under-test
    gf_isom_reset_data_offset(movie, &top_box_start);

    // Clean up
    gf_isom_close(movie);
    free(input_data); // Free the allocated memory

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
