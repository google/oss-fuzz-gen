#include <stdint.h>
#include <stddef.h>
#include <gpac/isomedia.h>
#include <gpac/internal/isomedia_dev.h> // Include internal header for the full definition of GF_ISOFile

int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;
    GF_Err result;

    // Create a temporary file to pass as fileName to gf_isom_open
    char tmp_filename[] = "/tmp/fuzz_input.mp4";
    FILE *tmp_file = fopen(tmp_filename, "wb");
    if (!tmp_file) {
        return 0;
    }

    // Write the input data to the temporary file
    fwrite(data, 1, size, tmp_file);
    fclose(tmp_file);

    // Create a new ISOFile for testing using gf_isom_open
    movie = gf_isom_open(tmp_filename, GF_ISOM_OPEN_READ, NULL);
    if (!movie) {
        return 0;
    }

    // Call the function-under-test
    gf_isom_reset_sample_count(movie);

    // Close the ISOFile after testing
    gf_isom_close(movie);

    // Remove the temporary file
    remove(tmp_filename);

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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
