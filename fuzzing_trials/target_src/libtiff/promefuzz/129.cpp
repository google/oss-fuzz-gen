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
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_129(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return 0;

    // Prepare data for LogLuv32toXYZ and LogLuv24toXYZ
    uint32_t logLuvValue;
    memcpy(&logLuvValue, Data, sizeof(uint32_t));
    float xyz[3] = {0.0f, 0.0f, 0.0f};

    // Fuzz LogLuv32toXYZ
    LogLuv32toXYZ(logLuvValue, xyz);

    // Fuzz TIFFSwabLong
    uint32_t swabLongValue = logLuvValue;
    TIFFSwabLong(&swabLongValue);

    // Fuzz LogLuv24toXYZ
    LogLuv24toXYZ(logLuvValue, xyz);

    // Prepare data for TIFFSwabArrayOfFloat
    tmsize_t numFloats = Size / sizeof(float);
    if (numFloats > 0) {
        float* floatArray = new float[numFloats];
        memcpy(floatArray, Data, numFloats * sizeof(float));

        // Fuzz TIFFSwabArrayOfFloat
        TIFFSwabArrayOfFloat(floatArray, numFloats);

        delete[] floatArray;
    }

    // Prepare data for LogLuv24fromXYZ and LogLuv32fromXYZ
    if (Size >= 3 * sizeof(float)) {
        float xyzInput[3];
        memcpy(xyzInput, Data, 3 * sizeof(float));

        // Fuzz LogLuv24fromXYZ
        uint32_t logLuv24 = LogLuv24fromXYZ(xyzInput, 1);

        // Fuzz LogLuv32fromXYZ
        uint32_t logLuv32 = LogLuv32fromXYZ(xyzInput, 1);
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

        LLVMFuzzerTestOneInput_129(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    