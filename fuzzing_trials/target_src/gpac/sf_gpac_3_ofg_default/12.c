#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;

    // Create a temporary file to simulate the ISO file from the buffer
    char temp_filename[] = "/tmp/fuzz_input_XXXXXX";
    int fd = mkstemp(temp_filename);
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

    // Attempt to open the ISO file from the temporary file
    movie = gf_isom_open(temp_filename, GF_ISOM_OPEN_READ, NULL);
    if (movie == NULL) {
        // Clean up the temporary file
        unlink(temp_filename);
        return 0;
    }

    // Call the function-under-test
    gf_isom_close(movie);

    // Clean up the temporary file
    unlink(temp_filename);

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
