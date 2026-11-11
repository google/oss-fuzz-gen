// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFNumberOfStrips at tif_strip.c:65:10 in tiffio.h
// TIFFStripSize at tif_strip.c:204:10 in tiffio.h
// _TIFFmalloc at tif_unix.c:333:7 in tiffio.h
// TIFFReadEncodedStrip at tif_read.c:543:10 in tiffio.h
// _TIFFfree at tif_unix.c:349:6 in tiffio.h
// TIFFYCbCrtoRGB at tif_color.c:199:6 in tiffio.h
// TIFFMergeFieldInfo at tif_dirinfo.c:1238:5 in tiffio.h
// TIFFScanlineSize at tif_strip.c:343:10 in tiffio.h
// TIFFNumberOfStrips at tif_strip.c:65:10 in tiffio.h
// _TIFFmalloc at tif_unix.c:333:7 in tiffio.h
// TIFFScanlineSize at tif_strip.c:343:10 in tiffio.h
// TIFFScanlineSize at tif_strip.c:343:10 in tiffio.h
// _TIFFfree at tif_unix.c:349:6 in tiffio.h
// TIFFNumberOfDirectories at tif_dir.c:2042:8 in tiffio.h
// TIFFSetDirectory at tif_dir.c:2067:5 in tiffio.h
// TIFFReadGPSDirectory at tif_dirread.c:5564:5 in tiffio.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <tiffio.h>
#include <cstring>

static TIFF* initializeTIFF(const char* filename) {
    TIFF* tif = TIFFOpen(filename, "r");
    if (!tif) {
        fprintf(stderr, "Failed to open TIFF file: %s\n", filename);
    }
    return tif;
}

static void fuzz_TIFFReadEncodedStrip(TIFF* tif, const uint8_t* Data, size_t Size) {
    if (!tif || Size < 4) return;

    uint32_t strip = *(reinterpret_cast<const uint32_t*>(Data)) % TIFFNumberOfStrips(tif);
    tmsize_t bufSize = TIFFStripSize(tif);
    void* buffer = _TIFFmalloc(bufSize);
    if (!buffer) return;

    TIFFReadEncodedStrip(tif, strip, buffer, bufSize);
    _TIFFfree(buffer);
}

static void fuzz_TIFFYCbCrtoRGB(const uint8_t* Data, size_t Size) {
    if (Size < sizeof(TIFFYCbCrToRGB) + 12) return;

    TIFFYCbCrToRGB* ycbcr = (TIFFYCbCrToRGB*)Data;
    uint32_t Y = *(reinterpret_cast<const uint32_t*>(Data + sizeof(TIFFYCbCrToRGB)));
    int32_t Cb = *(reinterpret_cast<const int32_t*>(Data + sizeof(TIFFYCbCrToRGB) + 4));
    int32_t Cr = *(reinterpret_cast<const int32_t*>(Data + sizeof(TIFFYCbCrToRGB) + 8));
    uint32_t R, G, B;

    TIFFYCbCrtoRGB(ycbcr, Y, Cb, Cr, &R, &G, &B);
}

static void fuzz_TIFFMergeFieldInfo(TIFF* tif, const uint8_t* Data, size_t Size) {
    if (!tif || Size < sizeof(TIFFFieldInfo)) return;

    const TIFFFieldInfo* fieldInfo = reinterpret_cast<const TIFFFieldInfo*>(Data);
    TIFFMergeFieldInfo(tif, fieldInfo, 1);
}

static void fuzz_TIFFWriteScanline(TIFF* tif, const uint8_t* Data, size_t Size) {
    if (!tif || Size < TIFFScanlineSize(tif) + 6) return;

    uint32_t row = *(reinterpret_cast<const uint32_t*>(Data)) % TIFFNumberOfStrips(tif);
    uint16_t sample = *(reinterpret_cast<const uint16_t*>(Data + 4));
    void* buffer = _TIFFmalloc(TIFFScanlineSize(tif));
    if (!buffer) return;

    memcpy(buffer, Data + 6, TIFFScanlineSize(tif));
    TIFFWriteScanline(tif, buffer, row, sample);
    _TIFFfree(buffer);
}

static void fuzz_TIFFSetDirectory(TIFF* tif, const uint8_t* Data, size_t Size) {
    if (!tif || Size < sizeof(tdir_t)) return;

    tdir_t dirn = *(reinterpret_cast<const tdir_t*>(Data)) % TIFFNumberOfDirectories(tif);
    TIFFSetDirectory(tif, dirn);
}

static void fuzz_TIFFReadGPSDirectory(TIFF* tif, const uint8_t* Data, size_t Size) {
    if (!tif || Size < sizeof(toff_t)) return;

    toff_t diroff = *(reinterpret_cast<const toff_t*>(Data));
    TIFFReadGPSDirectory(tif, diroff);
}

extern "C" int LLVMFuzzerTestOneInput_102(const uint8_t *Data, size_t Size) {
    const char* dummyFile = "./dummy_file";
    FILE* file = fopen(dummyFile, "wb");
    if (!file) return 0;

    fwrite(Data, 1, Size, file);
    fclose(file);

    TIFF* tif = initializeTIFF(dummyFile);
    if (!tif) return 0;

    fuzz_TIFFReadEncodedStrip(tif, Data, Size);
    fuzz_TIFFYCbCrtoRGB(Data, Size);
    fuzz_TIFFMergeFieldInfo(tif, Data, Size);
    fuzz_TIFFWriteScanline(tif, Data, Size);
    fuzz_TIFFSetDirectory(tif, Data, Size);
    fuzz_TIFFReadGPSDirectory(tif, Data, Size);

    if (tif) TIFFClose(tif);
    remove(dummyFile);

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

        LLVMFuzzerTestOneInput_102(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    