#include <tiffio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput_201(const uint8_t *data, size_t size) {
    // Create a temporary file to write the input data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // Failed to create temporary file
    }

    // Write the input data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpl);
        return 0; // Failed to write data
    }

    // Rewind the file descriptor to the beginning
    if (lseek(fd, 0, SEEK_SET) == -1) {
        close(fd);
        unlink(tmpl);
        return 0; // Failed to rewind file
    }

    // Open the TIFF file using TIFFFdOpen
    TIFF *tiff = TIFFFdOpen(fd, tmpl, "r");
    if (tiff != NULL) {
        // Successfully opened the TIFF file, perform operations
        // Close the TIFF file
        TIFFClose(tiff);
    }

    // Clean up
    close(fd);
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

    LLVMFuzzerTestOneInput_201(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
