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

extern "C" int LLVMFuzzerTestOneInput_140(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0; // Ensure there's enough data for a uint32_t

    // Prepare input for LogLuv32toXYZ and LogLuv24toXYZ
    uint32_t logluv_value = *reinterpret_cast<const uint32_t*>(Data);
    float xyz[3] = {0.0f, 0.0f, 0.0f};

    // Fuzz LogLuv32toXYZ
    LogLuv32toXYZ(logluv_value, xyz);

    // Fuzz TIFFSwabLong
    TIFFSwabLong(&logluv_value);

    // Fuzz LogLuv24toXYZ
    LogLuv24toXYZ(logluv_value, xyz);

    // Prepare input for TIFFSwabArrayOfFloat
    if (Size < 16) return 0; // Ensure there's enough data for four floats
    float float_array[4];
    memcpy(float_array, Data, 16);

    // Fuzz TIFFSwabArrayOfFloat
    TIFFSwabArrayOfFloat(float_array, 4);

    // Prepare input for LogLuv24fromXYZ
    uint32_t logluv24_result = LogLuv24fromXYZ(xyz, 1);

    // Prepare input for LogLuv32fromXYZ
    uint32_t logluv32_result = LogLuv32fromXYZ(xyz, 3);

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

        LLVMFuzzerTestOneInput_140(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    