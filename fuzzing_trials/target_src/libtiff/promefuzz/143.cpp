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
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <fstream>
#include "tiffio.h"

extern "C" int LLVMFuzzerTestOneInput_143(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) {
        return 0;
    }

    uint32_t logLuv32;
    memcpy(&logLuv32, Data, sizeof(uint32_t));

    // Prepare a float array for XYZ output
    float xyz[3] = {0.0f, 0.0f, 0.0f};

    // Test LogLuv32toXYZ
    LogLuv32toXYZ(logLuv32, xyz);

    // Test TIFFSwabLong
    uint32_t swabLong = logLuv32;
    TIFFSwabLong(&swabLong);

    // Test LogLuv24toXYZ
    uint32_t logLuv24;
    memcpy(&logLuv24, Data, sizeof(uint32_t));
    LogLuv24toXYZ(logLuv24, xyz);

    // Test TIFFSwabArrayOfFloat
    float floatArray[3] = {xyz[0], xyz[1], xyz[2]};
    TIFFSwabArrayOfFloat(floatArray, 3);

    // Test LogLuv24fromXYZ
    uint32_t resultLogLuv24 = LogLuv24fromXYZ(floatArray, 3);

    // Test LogLuv32fromXYZ
    uint32_t resultLogLuv32 = LogLuv32fromXYZ(floatArray, 3);

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

        LLVMFuzzerTestOneInput_143(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    