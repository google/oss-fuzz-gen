#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <cstring>

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_236(const uint8_t *data, size_t size) {
    TIFF *tiff;
    uint32_t tile = 0;
    void *buffer;
    tmsize_t bufferSize = static_cast<tmsize_t>(size);

    // Create a temporary file to use with TIFF
    char tmpl[] = "/tmp/fuzz-tiffXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    FILE *file = fdopen(fd, "wb+");
    if (!file) {
        close(fd);
        return 0;
    }

    // Initialize TIFF structure
    tiff = TIFFOpen(tmpl, "w+");
    if (!tiff) {
        fclose(file);
        return 0;
    }

    // Allocate memory for buffer and copy data
    buffer = malloc(bufferSize);
    if (!buffer) {
        TIFFClose(tiff);
        fclose(file);
        return 0;
    }
    memcpy(buffer, data, size);

    // Fuzz the function
    TIFFWriteRawTile(tiff, tile, buffer, bufferSize);

    // Clean up
    free(buffer);
    TIFFClose(tiff);
    fclose(file);
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

    LLVMFuzzerTestOneInput_236(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
