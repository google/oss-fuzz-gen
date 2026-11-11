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
#include <cstring>
#include <cstdio>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_138(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t) + sizeof(float) * 3) {
        return 0;
    }

    // Prepare data for LogLuv32toXYZ
    uint32_t logLuv32;
    float xyz32[3];
    memcpy(&logLuv32, Data, sizeof(uint32_t));
    LogLuv32toXYZ(logLuv32, xyz32);

    // Prepare data for TIFFSwabLong
    uint32_t swabLong;
    memcpy(&swabLong, Data, sizeof(uint32_t));
    TIFFSwabLong(&swabLong);

    // Prepare data for LogLuv24toXYZ
    uint32_t logLuv24;
    float xyz24[3];
    memcpy(&logLuv24, Data, sizeof(uint32_t));
    LogLuv24toXYZ(logLuv24, xyz24);

    // Prepare data for TIFFSwabArrayOfFloat
    size_t floatArraySize = (Size - sizeof(uint32_t)) / sizeof(float);
    float *floatArray = new float[floatArraySize];
    memcpy(floatArray, Data + sizeof(uint32_t), floatArraySize * sizeof(float));
    TIFFSwabArrayOfFloat(floatArray, static_cast<tmsize_t>(floatArraySize));

    // Prepare data for LogLuv24fromXYZ
    uint32_t luv24fromXYZ = LogLuv24fromXYZ(floatArray, static_cast<int>(floatArraySize));

    // Prepare data for LogLuv32fromXYZ
    uint32_t luv32fromXYZ = LogLuv32fromXYZ(floatArray, static_cast<int>(floatArraySize));

    // Clean up
    delete[] floatArray;

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

        LLVMFuzzerTestOneInput_138(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    