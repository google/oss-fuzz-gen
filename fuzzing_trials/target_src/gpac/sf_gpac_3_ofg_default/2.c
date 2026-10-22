#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;

    // Create a temporary file to write the input data
    char tmp_filename[] = "/tmp/fuzz_input_XXXXXX";
    int fd = mkstemp(tmp_filename);
    if (fd == -1) {
        return 0; // If we can't create a temp file, exit early
    }

    // Write the data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        remove(tmp_filename);
        return 0; // If we can't write the data, exit early
    }
    close(fd);

    // Open the ISO file using the temporary file name
    movie = gf_isom_open(tmp_filename, GF_ISOM_OPEN_READ, NULL);

    // Ensure that the movie is not NULL before calling gf_isom_close
    if (movie != NULL) {
        gf_isom_close(movie);
    }

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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
