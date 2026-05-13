#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h> // Include for close() and unlink()
#include <fcntl.h>  // Include for mkstemp()
#include "/src/gpac/include/gpac/isomedia.h"

int LLVMFuzzerTestOneInput_117(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;
    u32 timeScale = 1000;  // Default timescale value

    // Ensure we have enough data to create a movie
    if (size > 0) {
        // Create a temporary file to simulate an ISO media file
        char tmpl[] = "/tmp/fuzzmovieXXXXXX";
        int fd = mkstemp(tmpl);
        if (fd == -1) {
            return 0;
        }

        // Write the input data to the temporary file
        write(fd, data, size);
        close(fd);

        // Open the ISO media file using the temporary file
        movie = gf_isom_open(tmpl, GF_ISOM_OPEN_READ, NULL);

        // Remove the temporary file
        unlink(tmpl);
    }

    // Call the function-under-test
    gf_isom_set_timescale(movie, timeScale);

    // Clean up
    if (movie != NULL) {
        gf_isom_close(movie);
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

    LLVMFuzzerTestOneInput_117(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
