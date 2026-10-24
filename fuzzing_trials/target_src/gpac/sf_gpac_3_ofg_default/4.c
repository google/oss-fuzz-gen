#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <gpac/isomedia.h>

// Function to create an ISO file from memory
GF_ISOFile *create_iso_file_from_memory(const uint8_t *data, size_t size) {
    // Create a temporary file to write the data
    char tmp_file[] = "/tmp/fuzz_iso_XXXXXX";
    int fd = mkstemp(tmp_file);
    if (fd == -1) {
        return NULL;
    }

    // Write data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmp_file);
        return NULL;
    }
    close(fd);

    // Open the ISO file using the temporary file path
    GF_ISOFile *movie = gf_isom_open(tmp_file, GF_ISOM_OPEN_READ, NULL);

    // Clean up the temporary file
    unlink(tmp_file);

    return movie;
}

int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    // Ensure the size is large enough for meaningful data
    if (size == 0) {
        return 0;
    }

    // Create the ISO file from the input data
    GF_ISOFile *movie = create_iso_file_from_memory(data, size);
    if (movie == NULL) {
        return 0;
    }

    // Call the function under test
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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
