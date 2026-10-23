#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    GF_ISOFile *movie = NULL;

    // Create a temporary file to store the input data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the input data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }
    close(fd);

    // Open the ISO file from the temporary file
    movie = gf_isom_open(tmpl, GF_ISOM_OPEN_READ, NULL);
    if (movie == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    gf_isom_reset_sample_count(movie);

    // Close and clean up
    gf_isom_close(movie);
    unlink(tmpl);

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

    LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
