// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// LogLuv32toXYZ at tif_luv.c:1180:5 in tiffio.h
// TIFFSwabLong at tif_swab.c:45:6 in tiffio.h
// LogLuv24toXYZ at tif_luv.c:1032:5 in tiffio.h
// TIFFSwabArrayOfFloat at tif_swab.c:180:6 in tiffio.h
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

extern "C" int LLVMFuzzerTestOneInput_127(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) {
        return 0;
    }

    // Test LogLuv32toXYZ
    uint32_t logLuv32;
    memcpy(&logLuv32, Data, sizeof(uint32_t));
    float xyz32[3] = {0.0f, 0.0f, 0.0f};
    LogLuv32toXYZ(logLuv32, xyz32);

    // Test TIFFSwabLong
    uint32_t swabLong;
    memcpy(&swabLong, Data, sizeof(uint32_t));
    TIFFSwabLong(&swabLong);

    // Test LogLuv24toXYZ
    uint32_t logLuv24;
    if (Size >= sizeof(uint32_t) * 2) {
        memcpy(&logLuv24, Data + sizeof(uint32_t), sizeof(uint32_t));
        float xyz24[3] = {0.0f, 0.0f, 0.0f};
        LogLuv24toXYZ(logLuv24, xyz24);
    }

    // Test TIFFSwabArrayOfFloat
    if (Size >= sizeof(uint32_t) + sizeof(float) * 3) {
        tmsize_t n = (Size - sizeof(uint32_t)) / sizeof(float);
        // Allocate a new buffer to avoid modifying the const input
        float *floatArray = new float[n];
        memcpy(floatArray, Data + sizeof(uint32_t), n * sizeof(float));
        TIFFSwabArrayOfFloat(floatArray, n);
        delete[] floatArray;
    }

    // Test LogLuv24fromXYZ
    if (Size >= sizeof(uint32_t) + sizeof(float) * 3) {
        float xyzArray24[3];
        memcpy(xyzArray24, Data + sizeof(uint32_t), sizeof(float) * 3);
        int numPixels24 = 1;  // We are only passing one pixel
        LogLuv24fromXYZ(xyzArray24, numPixels24);
    }

    // Test LogLuv32fromXYZ
    if (Size >= sizeof(uint32_t) + sizeof(float) * 3) {
        float xyzArray32[3];
        memcpy(xyzArray32, Data + sizeof(uint32_t), sizeof(float) * 3);
        int numPixels32 = 1;  // We are only passing one pixel
        LogLuv32fromXYZ(xyzArray32, numPixels32);
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

        LLVMFuzzerTestOneInput_127(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    