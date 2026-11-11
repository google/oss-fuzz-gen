// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFStripSize at tif_strip.c:204:10 in tiffio.h
// _TIFFmalloc at tif_unix.c:333:7 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFNumberOfStrips at tif_strip.c:65:10 in tiffio.h
// TIFFReadEncodedStrip at tif_read.c:543:10 in tiffio.h
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

extern "C" int LLVMFuzzerTestOneInput_12(const uint8_t *Data, size_t Size) {
    // Create a TIFF handle using TIFFOpen
    TIFF *tif = TIFFOpen("./dummy_file", "w+");
    if (!tif) {
        return 0;
    }

    // Prepare a dummy file
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        TIFFClose(tif);
        return 0;
    }

    fwrite(Data, 1, Size, file);
    fclose(file);

    // Test TIFFStripSize
    tmsize_t strip_size = TIFFStripSize(tif);

    // Test _TIFFmalloc
    void *buffer = _TIFFmalloc(strip_size);
    if (!buffer) {
        TIFFClose(tif);
        return 0;
    }

    // Test TIFFNumberOfStrips
    uint32_t num_strips = TIFFNumberOfStrips(tif);

    // Test TIFFReadEncodedStrip
    for (uint32_t strip = 0; strip < num_strips; ++strip) {
        TIFFReadEncodedStrip(tif, strip, buffer, strip_size);
    }

    // Test _TIFFfree
    _TIFFfree(buffer);

    // Close the TIFF handle
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

        LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    