// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// XYZtoRGB24 at tif_luv.c:865:5 in tiffio.h
// LogLuv24toXYZ at tif_luv.c:1032:5 in tiffio.h
// TIFFCIELabToRGBInit at tif_color.c:135:5 in tiffio.h
// TIFFCIELabToXYZ at tif_color.c:43:6 in tiffio.h
// TIFFXYZToRGB at tif_color.c:89:6 in tiffio.h
// TIFFYCbCrToRGBInit at tif_color.c:251:5 in tiffio.h
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
#include <cstdlib>
#include <cstring>
#include <iostream>

static void TestXYZtoRGB24(const uint8_t *Data, size_t Size) {
    if (Size < 3 * sizeof(float) + 3 * sizeof(uint8_t)) return;

    float xyz[3];
    uint8_t rgb[3];

    memcpy(xyz, Data, 3 * sizeof(float));
    XYZtoRGB24(xyz, rgb);
}

static void TestLogLuv24toXYZ(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t) + 3 * sizeof(float)) return;

    uint32_t logluv;
    float xyz[3];

    memcpy(&logluv, Data, sizeof(uint32_t));
    LogLuv24toXYZ(logluv, xyz);
}

static void TestTIFFCIELabToRGBInit(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(TIFFCIELabToRGB) + sizeof(TIFFDisplay) + 3 * sizeof(float)) return;

    TIFFCIELabToRGB cielabToRGB;
    TIFFDisplay display;
    float refWhite[3];

    memcpy(&cielabToRGB, Data, sizeof(TIFFCIELabToRGB));
    memcpy(&display, Data + sizeof(TIFFCIELabToRGB), sizeof(TIFFDisplay));
    memcpy(refWhite, Data + sizeof(TIFFCIELabToRGB) + sizeof(TIFFDisplay), 3 * sizeof(float));

    TIFFCIELabToRGBInit(&cielabToRGB, &display, refWhite);
}

static void TestTIFFCIELabToXYZ(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(TIFFCIELabToRGB) + 3 * sizeof(uint32_t) + 3 * sizeof(float)) return;

    TIFFCIELabToRGB cielabToRGB;
    uint32_t L, a, b;
    float X, Y, Z;

    memcpy(&cielabToRGB, Data, sizeof(TIFFCIELabToRGB));
    memcpy(&L, Data + sizeof(TIFFCIELabToRGB), sizeof(uint32_t));
    memcpy(&a, Data + sizeof(TIFFCIELabToRGB) + sizeof(uint32_t), sizeof(uint32_t));
    memcpy(&b, Data + sizeof(TIFFCIELabToRGB) + 2 * sizeof(uint32_t), sizeof(uint32_t));

    TIFFCIELabToXYZ(&cielabToRGB, L, a, b, &X, &Y, &Z);
}

static void TestTIFFXYZToRGB(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(TIFFCIELabToRGB) + 3 * sizeof(float) + 3 * sizeof(uint32_t)) return;

    TIFFCIELabToRGB cielabToRGB;
    float X, Y, Z;
    uint32_t R, G, B;

    memcpy(&cielabToRGB, Data, sizeof(TIFFCIELabToRGB));
    memcpy(&X, Data + sizeof(TIFFCIELabToRGB), sizeof(float));
    memcpy(&Y, Data + sizeof(TIFFCIELabToRGB) + sizeof(float), sizeof(float));
    memcpy(&Z, Data + sizeof(TIFFCIELabToRGB) + 2 * sizeof(float), sizeof(float));

    TIFFXYZToRGB(&cielabToRGB, X, Y, Z, &R, &G, &B);
}

static void TestTIFFYCbCrToRGBInit(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(TIFFYCbCrToRGB) + 2 * 256 * sizeof(float)) return;

    TIFFYCbCrToRGB ycbcrToRGB;
    float luma[256];
    float refBlackWhite[256];

    memcpy(&ycbcrToRGB, Data, sizeof(TIFFYCbCrToRGB));
    memcpy(luma, Data + sizeof(TIFFYCbCrToRGB), 256 * sizeof(float));
    memcpy(refBlackWhite, Data + sizeof(TIFFYCbCrToRGB) + 256 * sizeof(float), 256 * sizeof(float));

    TIFFYCbCrToRGBInit(&ycbcrToRGB, luma, refBlackWhite);
}

extern "C" int LLVMFuzzerTestOneInput_68(const uint8_t *Data, size_t Size) {
    TestXYZtoRGB24(Data, Size);
    TestLogLuv24toXYZ(Data, Size);
    TestTIFFCIELabToRGBInit(Data, Size);
    TestTIFFCIELabToXYZ(Data, Size);
    TestTIFFXYZToRGB(Data, Size);
    TestTIFFYCbCrToRGBInit(Data, Size);

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

        LLVMFuzzerTestOneInput_68(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    