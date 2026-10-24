#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h> // Include for close and write functions

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
    // Create a temporary file to write the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        return 0;
    }

    // Close the file descriptor
    close(fd);

    // Open the TIFF file
    TIFF* tif = TIFFOpen(tmpl, "r");
    if (tif == nullptr) {
        return 0;
    }

    // Allocate a buffer for reading the strip
    tmsize_t bufferSize = 1024; // Arbitrary buffer size
    void* buffer = malloc(bufferSize);
    if (buffer == nullptr) {
        TIFFClose(tif);
        return 0;
    }

    // Read the encoded strip
    uint32_t stripIndex = 0; // Start with the first strip
    tmsize_t bytesRead = TIFFReadEncodedStrip(tif, stripIndex, buffer, bufferSize);

    // Clean up
    free(buffer);
    TIFFClose(tif);

    // Remove the temporary file
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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
