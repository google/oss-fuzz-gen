#include <stdint.h>
#include <stddef.h>
#include <gpac/isomedia.h>
#include <string.h>
#include <stdlib.h>

// Correct forward declaration of the function-under-test
void gf_isom_reset_sample_count(GF_ISOFile *isom_file);

int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    GF_ISOFile *movie;
    char *temp_file_name;

    // Check if size is sufficient to create a temporary file name
    if (size < 1) {
        return 0;
    }

    // Create a temporary file name from the input data
    temp_file_name = strndup((const char*)data, size);
    if (!temp_file_name) {
        return 0;
    }

    // Initialize the GF_ISOFile structure
    movie = gf_isom_open(temp_file_name, GF_ISOM_OPEN_READ, NULL);

    // Free the temporary file name
    free(temp_file_name);

    // Check if the movie was successfully opened
    if (movie == NULL) {
        return 0;
    }

    // Call the function-under-test
    gf_isom_reset_sample_count(movie);

    // Close the movie file
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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
