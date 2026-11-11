#include <tiffio.h>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <unistd.h> // Include for close() and write()
#include <sys/types.h> // Include for ssize_t

extern "C" int LLVMFuzzerTestOneInput_43(const uint8_t *data, size_t size) {
    // Create a temporary file to simulate a TIFF file
    char tmpl[] = "/tmp/fuzz_tiffXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return 0;
    }

    // Close the file descriptor to flush the data
    close(fd);

    // Open the temporary file as a TIFF file
    TIFF *tif = TIFFOpen(tmpl, "r");
    if (tif == nullptr) {
        remove(tmpl);
        return 0;
    }

    // Allocate a buffer for reading the raw tile
    tmsize_t bufferSize = 1024; // Arbitrary buffer size
    void *buffer = malloc(bufferSize);
    if (buffer == nullptr) {
        TIFFClose(tif);
        remove(tmpl);
        return 0;
    }

    // Call the function-under-test
    uint32_t tile = 0; // Tile index
    tmsize_t bytesRead = TIFFReadRawTile(tif, tile, buffer, bufferSize);

    // Clean up
    free(buffer);
    TIFFClose(tif);
    remove(tmpl);

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

    LLVMFuzzerTestOneInput_43(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
