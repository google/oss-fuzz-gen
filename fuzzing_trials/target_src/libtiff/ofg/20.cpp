#include <tiffio.h>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>  // For close() and write()
#include <cstring>   // For memcpy()

extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    TIFF *tiff = nullptr;
    void *buffer = nullptr;
    uint32_t x = 0, y = 0, z = 0;
    uint16_t sample = 0;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);

    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to a temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        return 0;
    }
    close(fd);

    // Open the temporary file with TIFFOpen
    tiff = TIFFOpen(tmpl, "w");
    if (!tiff) {
        return 0;
    }

    // Allocate buffer for the tile data
    buffer = malloc(size);
    if (!buffer) {
        TIFFClose(tiff);
        return 0;
    }

    // Initialize buffer with data
    memcpy(buffer, data, size);

    // Call the function-under-test
    TIFFWriteTile(tiff, buffer, x, y, z, sample);

    // Clean up
    free(buffer);
    TIFFClose(tiff);
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

    LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
