// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// XYZtoRGB24 at tif_luv.c:865:5 in tiffio.h
// LogLuv24toXYZ at tif_luv.c:1032:5 in tiffio.h
// TIFFSwabArrayOfFloat at tif_swab.c:180:6 in tiffio.h
// TIFFCIELabToXYZ at tif_color.c:43:6 in tiffio.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_59(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(float) * 3 + sizeof(uint32_t)) {
        return 0; // Not enough data
    }

    // Prepare XYZ data and RGB output buffer for XYZtoRGB24
    float xyzData[3];
    uint8_t rgbData[3];
    memcpy(xyzData, Data, sizeof(float) * 3);
    XYZtoRGB24(xyzData, rgbData);

    // Prepare LogLuv data for LogLuv24toXYZ
    uint32_t logLuvData;
    memcpy(&logLuvData, Data + sizeof(float) * 3, sizeof(uint32_t));
    float xyzOutput[3];
    LogLuv24toXYZ(logLuvData, xyzOutput);

    // Prepare float array for TIFFSwabArrayOfFloat
    tmsize_t numFloats = (Size - sizeof(float) * 3 - sizeof(uint32_t)) / sizeof(float);
    if (numFloats > 0) {
        // Allocate a new buffer to avoid overwriting const input
        float *floatArray = new float[numFloats];
        memcpy(floatArray, Data + sizeof(float) * 3 + sizeof(uint32_t), numFloats * sizeof(float));
        TIFFSwabArrayOfFloat(floatArray, numFloats);
        delete[] floatArray;
    }

    // Prepare for TIFFCIELabToXYZ
    TIFFCIELabToRGB cielab;
    uint32_t L = static_cast<uint32_t>(Data[0]);
    int32_t a = static_cast<int32_t>(Data[1]);
    int32_t b = static_cast<int32_t>(Data[2]);
    float X, Y, Z;
    TIFFCIELabToXYZ(&cielab, L, a, b, &X, &Y, &Z);

    // Prepare for LogLuv24fromXYZ
    uint32_t logLuv24 = LogLuv24fromXYZ(xyzData, 1);

    // Prepare for LogLuv32fromXYZ
    uint32_t logLuv32 = LogLuv32fromXYZ(xyzData, 1);

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

        LLVMFuzzerTestOneInput_59(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    