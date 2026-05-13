// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// _TIFFmalloc at tif_unix.c:333:7 in tiffio.h
// TIFFReadEncodedStrip at tif_read.c:543:10 in tiffio.h
// _TIFFfree at tif_unix.c:349:6 in tiffio.h
// TIFFYCbCrtoRGB at tif_color.c:199:6 in tiffio.h
// TIFFMergeFieldInfo at tif_dirinfo.c:1238:5 in tiffio.h
// TIFFSetDirectory at tif_dir.c:2067:5 in tiffio.h
// TIFFReadGPSDirectory at tif_dirread.c:5564:5 in tiffio.h
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

static TIFF* openDummyTIFF() {
    FILE* file = fopen("./dummy_file", "wb+");
    if (!file) return nullptr;
    fclose(file);
    return TIFFOpen("./dummy_file", "r+");
}

static void fuzz_TIFFReadEncodedStrip(TIFF* tif, const uint8_t* Data, size_t Size) {
    if (Size < sizeof(uint32_t) + sizeof(tmsize_t)) return;
    uint32_t strip = *reinterpret_cast<const uint32_t*>(Data);
    tmsize_t bufSize = *reinterpret_cast<const tmsize_t*>(Data + sizeof(uint32_t));

    void* buf = _TIFFmalloc(bufSize);
    if (!buf) return;

    TIFFReadEncodedStrip(tif, strip, buf, bufSize);
    _TIFFfree(buf);
}

static void fuzz_TIFFYCbCrtoRGB(const uint8_t* Data, size_t Size) {
    if (Size < sizeof(TIFFYCbCrToRGB) + 3 * sizeof(int32_t)) return;

    TIFFYCbCrToRGB* ycbcr = reinterpret_cast<TIFFYCbCrToRGB*>(const_cast<uint8_t*>(Data));
    uint32_t Y = *reinterpret_cast<const uint32_t*>(Data + sizeof(TIFFYCbCrToRGB));
    int32_t Cb = *reinterpret_cast<const int32_t*>(Data + sizeof(TIFFYCbCrToRGB) + sizeof(uint32_t));
    int32_t Cr = *reinterpret_cast<const int32_t*>(Data + sizeof(TIFFYCbCrToRGB) + sizeof(uint32_t) + sizeof(int32_t));

    uint32_t R, G, B;
    TIFFYCbCrtoRGB(ycbcr, Y, Cb, Cr, &R, &G, &B);
}

static void fuzz_TIFFMergeFieldInfo(TIFF* tif, const uint8_t* Data, size_t Size) {
    if (Size < sizeof(TIFFFieldInfo) + sizeof(uint32_t)) return;

    const TIFFFieldInfo* fieldInfo = reinterpret_cast<const TIFFFieldInfo*>(Data);
    uint32_t fieldCount = *reinterpret_cast<const uint32_t*>(Data + sizeof(TIFFFieldInfo));

    TIFFMergeFieldInfo(tif, fieldInfo, fieldCount);
}

static void fuzz_TIFFWriteScanline(TIFF* tif, const uint8_t* Data, size_t Size) {
    if (Size < sizeof(uint32_t) + sizeof(uint16_t)) return;

    void* buf = const_cast<uint8_t*>(Data);
    uint32_t row = *reinterpret_cast<const uint32_t*>(Data);
    uint16_t sample = *reinterpret_cast<const uint16_t*>(Data + sizeof(uint32_t));

    TIFFWriteScanline(tif, buf, row, sample);
}

static void fuzz_TIFFSetDirectory(TIFF* tif, const uint8_t* Data, size_t Size) {
    if (Size < sizeof(tdir_t)) return;

    tdir_t dirn = *reinterpret_cast<const tdir_t*>(Data);
    TIFFSetDirectory(tif, dirn);
}

static void fuzz_TIFFReadGPSDirectory(TIFF* tif, const uint8_t* Data, size_t Size) {
    if (Size < sizeof(toff_t)) return;

    toff_t diroff = *reinterpret_cast<const toff_t*>(Data);
    TIFFReadGPSDirectory(tif, diroff);
}

extern "C" int LLVMFuzzerTestOneInput_104(const uint8_t *Data, size_t Size) {
    TIFF* tif = openDummyTIFF();
    if (!tif) return 0;

    fuzz_TIFFReadEncodedStrip(tif, Data, Size);
    fuzz_TIFFYCbCrtoRGB(Data, Size);
    fuzz_TIFFMergeFieldInfo(tif, Data, Size);
    fuzz_TIFFWriteScanline(tif, Data, Size);
    fuzz_TIFFSetDirectory(tif, Data, Size);
    fuzz_TIFFReadGPSDirectory(tif, Data, Size);

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

        LLVMFuzzerTestOneInput_104(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    