#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "/src/gpac/include/gpac/isomedia.h"
#include <unistd.h>

int LLVMFuzzerTestOneInput_172(const uint8_t *data, size_t size) {
    GF_ISOFile *movie;
    GF_ISOOpenMode mode;

    // Create a temporary file
    char tmp_filename[] = "/tmp/fuzz_input_XXXXXX";
    int fd = mkstemp(tmp_filename);
    if (fd == -1) {
        return 0; // Return if unable to create a temporary file
    }

    // Write the data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmp_filename);
        return 0; // Return if unable to write all data
    }

    // Close the file descriptor, we will use the file path
    close(fd);

    // Initialize the GF_ISOFile structure
    movie = gf_isom_open(tmp_filename, GF_ISOM_OPEN_READ, NULL);
    if (!movie) {
        unlink(tmp_filename);
        return 0; // Return if unable to open the file
    }

    // Set the mode to a valid value
    mode = GF_ISOM_OPEN_READ;

    // Call the function-under-test
    gf_isom_can_access_movie(movie, mode);

    // Close the movie file
    gf_isom_close(movie);

    // Clean up the temporary file
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

    LLVMFuzzerTestOneInput_172(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
