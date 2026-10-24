// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFSetDirectory at tif_dir.c:2067:5 in tiffio.h
// TIFFCurrentDirOffset at tif_dir.c:2233:10 in tiffio.h
// TIFFNumberOfTiles at tif_tile.c:108:10 in tiffio.h
// TIFFTileSize64 at tif_tile.c:249:10 in tiffio.h
// _TIFFmalloc at tif_unix.c:333:7 in tiffio.h
// TIFFReadEncodedTile at tif_read.c:963:10 in tiffio.h
// _TIFFfree at tif_unix.c:349:6 in tiffio.h
// TIFFScanlineSize64 at tif_strip.c:257:10 in tiffio.h
// _TIFFmalloc at tif_unix.c:333:7 in tiffio.h
// _TIFFfree at tif_unix.c:349:6 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <tiffio.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cassert>

static TIFF* initializeTIFF(const uint8_t* Data, size_t Size) {
    FILE* file = fopen("./dummy_file", "wb");
    if (!file) return nullptr;
    fwrite(Data, 1, Size, file);
    fclose(file);

    TIFF* tif = TIFFOpen("./dummy_file", "r");
    return tif;
}

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return 0;

    TIFF* tif = initializeTIFF(Data, Size);
    if (!tif) return 0;

    tdir_t dirNumber = *reinterpret_cast<const tdir_t*>(Data);

    // TIFFSetDirectory
    if (TIFFSetDirectory(tif, dirNumber)) {
        // TIFFCurrentDirOffset
        uint64_t dirOffset = TIFFCurrentDirOffset(tif);
        (void)dirOffset; // Use the offset if needed

        // TIFFNumberOfTiles
        uint32_t numTiles = TIFFNumberOfTiles(tif);
        
        // TIFFTileSize64
        uint64_t tileSize = TIFFTileSize64(tif);

        // TIFFReadEncodedTile
        if (numTiles > 0 && tileSize > 0) {
            void* buf = _TIFFmalloc(tileSize);
            if (buf) {
                tmsize_t readSize = TIFFReadEncodedTile(tif, 0, buf, tileSize);
                (void)readSize; // Use the read size if needed
                _TIFFfree(buf);
            }
        }

        // TIFFScanlineSize64
        uint64_t scanlineSize = TIFFScanlineSize64(tif);

        // TIFFReadScanline
        if (scanlineSize > 0) {
            void* scanlineBuf = _TIFFmalloc(scanlineSize);
            if (scanlineBuf) {
                TIFFReadScanline(tif, scanlineBuf, 0, 0);
                _TIFFfree(scanlineBuf);
            }
        }
    }

    // TIFFClose
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

        LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    