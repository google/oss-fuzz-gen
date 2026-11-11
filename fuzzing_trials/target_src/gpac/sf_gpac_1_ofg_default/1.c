#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // Include for mkstemp and close
#include <gpac/isomedia.h>

// Assuming GF_EXPORT is defined as part of the GPAC library
// and GF_ISOFile is a structure defined within the same library.

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;
    FILE *temp_file = NULL;
    char temp_filename[] = "/tmp/fuzz_temp_XXXXXX";

    // Create a temporary file to write the buffer data
    int fd = mkstemp(temp_filename);
    if (fd == -1) {
        return 0;
    }

    temp_file = fdopen(fd, "wb");
    if (!temp_file) {
        close(fd);
        return 0;
    }

    // Write the data to the temporary file
    if (fwrite(data, 1, size, temp_file) != size) {
        fclose(temp_file);
        remove(temp_filename);
        return 0;
    }

    fclose(temp_file);

    // Open the ISO media file from the temporary file
    movie = gf_isom_open(temp_filename, GF_ISOM_OPEN_READ, "/tmp");

    if (movie != NULL) {
        // Call the function-under-test
        gf_isom_reset_sample_count(movie);

        // Close the movie file after testing
        gf_isom_close(movie);
    }

    // Clean up the temporary file
    remove(temp_filename);

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

    LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
