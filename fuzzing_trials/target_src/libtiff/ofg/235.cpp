#include <cstdint>
#include <cstdlib>
#include <tiffio.h>
#include <unistd.h> // For close and unlink
#include <cstring>  // For memcpy

extern "C" int LLVMFuzzerTestOneInput_235(const uint8_t *data, size_t size) {
    // Initialize variables
    TIFF *tiff = nullptr;
    uint32_t tile = 0;
    void *buf = nullptr;
    tmsize_t bufsize = static_cast<tmsize_t>(size);

    // Create a temporary file to work with TIFF functions
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Open the TIFF file
    tiff = TIFFFdOpen(fd, tmpl, "w");
    if (!tiff) {
        close(fd);
        return 0;
    }

    // Allocate buffer and copy data
    buf = malloc(bufsize);
    if (!buf) {
        TIFFClose(tiff);
        close(fd);
        return 0;
    }
    memcpy(buf, data, size);

    // Call the function-under-test
    TIFFWriteRawTile(tiff, tile, buf, bufsize);

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

    LLVMFuzzerTestOneInput_235(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
