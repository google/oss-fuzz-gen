#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <unistd.h> // For close() and unlink()

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    // Create a temporary TIFF file in memory
    char tmpl[] = "/tmp/fuzz-tiff-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    TIFF *tiff = TIFFOpen(tmpl, "w");
    if (!tiff) {
        close(fd);
        return 0;
    }

    // Initialize parameters for TIFFWriteTile
    void *buf = malloc(size);
    if (!buf) {
        TIFFClose(tiff);
        close(fd);
        return 0;
    }
    memcpy(buf, data, size);

    uint32_t x = 0; // Assuming starting at the beginning of the tile
    uint32_t y = 0; // Assuming starting at the beginning of the tile
    uint32_t z = 0; // Assuming no depth (2D image)
    uint16_t sample = 0; // Assuming first sample

    // Call the function-under-test
    tmsize_t result = TIFFWriteTile(tiff, buf, x, y, z, sample);

    // Clean up
    free(buf);
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

    LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
