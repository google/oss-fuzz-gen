#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // Include for close() and unlink()
#include <fcntl.h>  // Include for mkstemp()
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_86(const uint8_t *data, size_t size) {
    GF_ISOFile *movie;
    char filename[] = "/tmp/fuzzfileXXXXXX";
    int fd;

    // Ensure that the data size is sufficient to create a temporary file
    if (size == 0) {
        return 0;
    }

    // Create a temporary file to use as the filename
    fd = mkstemp(filename);
    if (fd == -1) {
        return 0;
    }

    // Write the data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        return 0;
    }

    // Close the file descriptor
    close(fd);

    // Initialize movie to a non-NULL value
    movie = gf_isom_open(filename, GF_ISOM_OPEN_READ, NULL);

    // Call the function-under-test
    gf_isom_set_final_name(movie, filename);

    // Clean up
    if (movie) {
        gf_isom_close(movie);
    }

    // Remove the temporary file
    unlink(filename);

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

    LLVMFuzzerTestOneInput_86(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
