#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <cstdio> // Added for mkstemp
#include <cstdlib> // Added for mkstemp

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_174(const uint8_t *data, size_t size) {
    // Initialize necessary variables
    TIFF *tiff = NULL;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);

    if (fd == -1) {
        return 0; // Failed to create temporary file
    }

    // Write the input data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);
        return 0; // Failed to write all data
    }

    // Rewind the file descriptor to the beginning
    lseek(fd, 0, SEEK_SET);

    // Open the TIFF file
    tiff = TIFFFdOpen(fd, tmpl, "r+");
    if (tiff == NULL) {
        close(fd);
        unlink(tmpl);
        return 0; // Failed to open TIFF
    }

    // Call the function-under-test
    TIFFCreateEXIFDirectory(tiff);

    // Clean up
    TIFFClose(tiff);
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

    LLVMFuzzerTestOneInput_174(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
