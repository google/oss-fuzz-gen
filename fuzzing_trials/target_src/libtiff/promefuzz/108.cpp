// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFNumberOfStrips at tif_strip.c:65:10 in tiffio.h
// TIFFStripSize at tif_strip.c:204:10 in tiffio.h
// _TIFFmalloc at tif_unix.c:333:7 in tiffio.h
// TIFFReadEncodedStrip at tif_read.c:543:10 in tiffio.h
// _TIFFfree at tif_unix.c:349:6 in tiffio.h
// TIFFCurrentStrip at tif_open.c:879:10 in tiffio.h
// TIFFDefaultStripSize at tif_strip.c:218:10 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// _TIFFmalloc at tif_unix.c:333:7 in tiffio.h
// TIFFWriteEncodedStrip at tif_write.c:215:10 in tiffio.h
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
#include <cstdlib>
#include <cstring>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

extern "C" int LLVMFuzzerTestOneInput_108(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there's at least some data to work with

    write_dummy_file(Data, Size);

    TIFF *tif = TIFFOpen("./dummy_file", "r");
    if (!tif) return 0;

    uint32_t strip_count = TIFFNumberOfStrips(tif);
    if (strip_count > 0) {
        tmsize_t strip_size = TIFFStripSize(tif);
        void *buffer = _TIFFmalloc(strip_size);
        if (buffer) {
            for (uint32_t strip = 0; strip < strip_count; ++strip) {
                TIFFReadEncodedStrip(tif, strip, buffer, strip_size);
            }
            _TIFFfree(buffer);
        }
    }

    uint32_t current_strip = TIFFCurrentStrip(tif);
    uint32_t default_strip_size = TIFFDefaultStripSize(tif, static_cast<uint32_t>(Size));

    TIFFClose(tif);

    // Attempt to open the file for writing and test TIFFWriteEncodedStrip
    tif = TIFFOpen("./dummy_file", "r+");
    if (tif) {
        if (strip_count > 0) {
            void *buffer = _TIFFmalloc(Size);
            if (buffer) {
                memcpy(buffer, Data, Size);
                TIFFWriteEncodedStrip(tif, current_strip, buffer, static_cast<tmsize_t>(Size));
                _TIFFfree(buffer);
            }
        }
        TIFFClose(tif);
    }

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

        LLVMFuzzerTestOneInput_108(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    