#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // Include this for mkstemp and close
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_85(const uint8_t *data, size_t size) {
    GF_ISOFile *movie;
    char filename[] = "/tmp/fuzzfileXXXXXX";
    int fd;

    // Ensure the data size is sufficient for creating a temporary file
    if (size == 0) {
        return 0;
    }

    // Create a temporary file to use as the filename
    fd = mkstemp(filename);
    if (fd == -1) {
        return 0;
    }
    close(fd);

    // Initialize the GF_ISOFile structure
    movie = gf_isom_open(filename, GF_ISOM_OPEN_WRITE, NULL);
    if (movie == NULL) {
        return 0;
    }

    // Call the function-under-test
    gf_isom_set_final_name(movie, filename);

    // Clean up
    gf_isom_close(movie);

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

    LLVMFuzzerTestOneInput_85(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
