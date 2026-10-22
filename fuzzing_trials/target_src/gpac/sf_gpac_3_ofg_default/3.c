#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;

    // Initialize the movie with some data
    // For fuzzing, we'll assume the data is an ISO file content
    // Create a temporary file to simulate the movie file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the data to the temporary file
    write(fd, data, size);
    close(fd);

    // Open the ISO file using the temporary filename
    movie = gf_isom_open(tmpl, GF_ISOM_OPEN_READ, NULL);

    // Call the function-under-test
    if (movie != NULL) {
        gf_isom_close(movie);
    }

    // Clean up the temporary file
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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
