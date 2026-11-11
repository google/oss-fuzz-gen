#include <stdio.h>
#include <stdint.h>
#include <zlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

// Helper function to create a temporary file with the given data
static gzFile create_temp_gz_file(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return NULL;
    }

    // Write data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);
        return NULL;
    }

    // Close the file descriptor
    close(fd);

    // Open the file with gzopen for reading
    gzFile gz = gzopen(tmpl, "rb");
    unlink(tmpl); // Remove the file after opening it
    return gz;
}

int LLVMFuzzerTestOneInput_121(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Create a temporary gz file from the input data
    gzFile gz = create_temp_gz_file(data, size);
    if (gz == NULL) {
        return 0;
    }

    // Call the function-under-test
    gzclose_r(gz);

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

    LLVMFuzzerTestOneInput_121(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
