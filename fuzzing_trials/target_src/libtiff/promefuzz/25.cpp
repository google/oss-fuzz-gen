// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// LogLuv32toXYZ at tif_luv.c:1180:5 in tiffio.h
// LogLuv24toXYZ at tif_luv.c:1032:5 in tiffio.h
// TIFFSwabLong at tif_swab.c:45:6 in tiffio.h
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

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0; // Ensure there's enough data for a uint32_t

    // Prepare data for LogLuv32toXYZ and LogLuv24toXYZ
    uint32_t logluv32 = 0;
    uint32_t logluv24 = 0;
    memcpy(&logluv32, Data, sizeof(uint32_t));
    memcpy(&logluv24, Data, sizeof(uint32_t));

    float xyz[3] = {0.0f, 0.0f, 0.0f};

    // Call LogLuv32toXYZ
    LogLuv32toXYZ(logluv32, xyz);

    // Call LogLuv24toXYZ
    LogLuv24toXYZ(logluv24, xyz);

    // Prepare data for TIFFSwabLong
    uint32_t swabLong = logluv32;

    // Call TIFFSwabLong
    TIFFSwabLong(&swabLong);

    // Prepare data for TIFFSwabArrayOfFloat
    float floatArray[3] = {xyz[0], xyz[1], xyz[2]};

    // Call TIFFSwabArrayOfFloat
    TIFFSwabArrayOfFloat(floatArray, 3);

    // Call LogLuv24fromXYZ
    uint32_t luv24 = LogLuv24fromXYZ(floatArray, 3);

    // Call LogLuv32fromXYZ
    uint32_t luv32 = LogLuv32fromXYZ(floatArray, 3);

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

        LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    