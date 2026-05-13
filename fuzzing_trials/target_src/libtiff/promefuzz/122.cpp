// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFStripSize at tif_strip.c:204:10 in tiffio.h
// _TIFFmalloc at tif_unix.c:333:7 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFReadEncodedStrip at tif_read.c:543:10 in tiffio.h
// TIFFTileSize at tif_tile.c:253:10 in tiffio.h
// _TIFFmalloc at tif_unix.c:333:7 in tiffio.h
// _TIFFfree at tif_unix.c:349:6 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFReadEncodedTile at tif_read.c:963:10 in tiffio.h
// TIFFReadFromUserBuffer at tif_read.c:1555:5 in tiffio.h
// _TIFFmalloc at tif_unix.c:333:7 in tiffio.h
// _TIFFfree at tif_unix.c:349:6 in tiffio.h
// _TIFFfree at tif_unix.c:349:6 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFWriteEncodedStrip at tif_write.c:215:10 in tiffio.h
// _TIFFfree at tif_unix.c:349:6 in tiffio.h
// _TIFFfree at tif_unix.c:349:6 in tiffio.h
// _TIFFfree at tif_unix.c:349:6 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
#include <tiffio.h>
#include <cstdio>
#include <cstdint>
#include <cstddef>

extern "C" int LLVMFuzzerTestOneInput_122(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Write the input data to the dummy file
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Open the dummy file with libtiff
    TIFF *tif = TIFFOpen("./dummy_file", "r");
    if (!tif) return 0;

    // Prepare a buffer for reading a strip
    tmsize_t stripSize = TIFFStripSize(tif);
    void *buffer = _TIFFmalloc(stripSize);
    if (!buffer) {
        TIFFClose(tif);
        return 0;
    }

    // Fuzz TIFFReadEncodedStrip
    TIFFReadEncodedStrip(tif, 0, buffer, stripSize);

    // Fuzz TIFFPrintDirectory
    file = fopen("./dummy_output", "w");
    if (file) {
        TIFFPrintDirectory(tif, file, 0);
        fclose(file);
    }

    // Prepare a buffer for reading a tile
    tmsize_t tileSize = TIFFTileSize(tif);
    void *tileBuffer = _TIFFmalloc(tileSize);
    if (!tileBuffer) {
        _TIFFfree(buffer);
        TIFFClose(tif);
        return 0;
    }

    // Fuzz TIFFReadEncodedTile
    TIFFReadEncodedTile(tif, 0, tileBuffer, tileSize);

    // Fuzz TIFFReadFromUserBuffer
    TIFFReadFromUserBuffer(tif, 0, (void *)Data, (tmsize_t)Size, buffer, stripSize);

    // Prepare data for writing
    void *writeData = _TIFFmalloc(stripSize);
    if (!writeData) {
        _TIFFfree(buffer);
        _TIFFfree(tileBuffer);
        TIFFClose(tif);
        return 0;
    }

    // Fuzz TIFFWriteEncodedStrip
    TIFFWriteEncodedStrip(tif, 0, writeData, stripSize);

    // Cleanup
    _TIFFfree(buffer);
    _TIFFfree(tileBuffer);
    _TIFFfree(writeData);
    TIFFClose(tif);

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

        LLVMFuzzerTestOneInput_122(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    