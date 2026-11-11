#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <gpac/isomedia.h>
#include <gpac/internal/isomedia_dev.h> // Include internal headers for development functions

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;
    GF_Err err;

    // Create a temporary file to simulate file input
    FILE *temp_file = tmpfile();
    if (!temp_file) {
        return 0; // If the temporary file cannot be created, exit early
    }

    // Write the input data to the temporary file
    if (fwrite(data, 1, size, temp_file) != size) {
        fclose(temp_file);
        return 0; // If writing fails, exit early
    }

    // Rewind the file to the beginning for reading
    rewind(temp_file);

    // Open the temporary file using gf_isom_open_file
    err = gf_isom_open_file(temp_file, &movie, GF_ISOM_OPEN_READ);

    if (err != GF_OK || movie == NULL) {
        fclose(temp_file);
        return 0; // If movie initialization fails, exit early
    }

    // Call the function-under-test
    gf_isom_reset_sample_count(movie);

    // Clean up and close the movie
    gf_isom_close(movie);
    fclose(temp_file); // Close the temporary file

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
