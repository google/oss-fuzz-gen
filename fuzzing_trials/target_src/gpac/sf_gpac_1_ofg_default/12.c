#include <stdint.h>
#include <stddef.h>
#include <unistd.h> // Include for mkstemp, write, close, and unlink functions
#include <fcntl.h>  // Include for open flags
#include <gpac/isomedia.h> // Include the necessary header for GF_ISOFile and related functions

int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    GF_ISOFile *movie = NULL;

    // Check if the input size is valid for creating a movie
    if (size > 0) {
        // Create a temporary file to simulate an ISO media file
        char tmpl[] = "/tmp/fuzzfileXXXXXX";
        int fd = mkstemp(tmpl);
        if (fd == -1) {
            return 0;
        }

        // Write the fuzz data to the temporary file
        write(fd, data, size);
        close(fd);

        // Open the ISO media file using the GPAC library function
        movie = gf_isom_open(tmpl, GF_ISOM_OPEN_READ, NULL);

        // Call the function-under-test if the movie is successfully opened
        if (movie != NULL) {
            gf_isom_reset_sample_count(movie);

            // Close the movie after testing
            gf_isom_close(movie);
        }

        // Remove the temporary file
        unlink(tmpl);
    }

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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
