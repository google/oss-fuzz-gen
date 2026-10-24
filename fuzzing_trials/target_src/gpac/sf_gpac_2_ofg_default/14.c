#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;
    u64 top_box_start_val = 0;
    u64 *top_box_start = &top_box_start_val;

    // Create a temporary file to write the input data
    char tmp_filename[] = "/tmp/fuzz_input.XXXXXX";
    int fd = mkstemp(tmp_filename);
    if (fd == -1) {
        return 0; // If the temp file cannot be created, exit early
    }

    // Write the input data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmp_filename);
        return 0; // If writing fails, exit early
    }
    close(fd);

    // Initialize the movie object using the correct function signature
    movie = gf_isom_open(tmp_filename, GF_ISOM_OPEN_READ, NULL);
    if (movie == NULL) {
        unlink(tmp_filename);
        return 0; // If the movie cannot be initialized, exit early
    }

    // Call the function under test
    gf_isom_reset_data_offset(movie, top_box_start);

    // Clean up
    gf_isom_close(movie);
    unlink(tmp_filename);

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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
