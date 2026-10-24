// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// XYZtoRGB24 at tif_luv.c:865:5 in tiffio.h
// TIFFSwabFloat at tif_swab.c:165:6 in tiffio.h
// LogLuv24toXYZ at tif_luv.c:1032:5 in tiffio.h
// TIFFSwabArrayOfFloat at tif_swab.c:180:6 in tiffio.h
// TIFFCIELabToXYZ at tif_color.c:43:6 in tiffio.h
// TIFFXYZToRGB at tif_color.c:89:6 in tiffio.h
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

extern "C" int LLVMFuzzerTestOneInput_51(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(float) * 3 + sizeof(uint32_t)) {
        return 0;
    }

    // Create a copy of the input data to avoid modifying the const input
    std::vector<uint8_t> dataCopy(Data, Data + Size);

    // Prepare data for XYZtoRGB24
    float xyz[3];
    memcpy(xyz, dataCopy.data(), sizeof(float) * 3);
    uint8_t rgb[3] = {0};

    // Fuzz XYZtoRGB24
    XYZtoRGB24(xyz, rgb);

    // Prepare data for TIFFSwabFloat
    float swabFloat;
    memcpy(&swabFloat, dataCopy.data(), sizeof(float));

    // Fuzz TIFFSwabFloat
    TIFFSwabFloat(&swabFloat);

    // Prepare data for LogLuv24toXYZ
    uint32_t logLuv;
    memcpy(&logLuv, dataCopy.data(), sizeof(uint32_t));
    float logLuvXYZ[3] = {0};

    // Fuzz LogLuv24toXYZ
    LogLuv24toXYZ(logLuv, logLuvXYZ);

    // Prepare data for TIFFSwabArrayOfFloat
    tmsize_t n = (Size - sizeof(float) * 3) / sizeof(float);
    float *swabArray = reinterpret_cast<float *>(dataCopy.data() + sizeof(float) * 3);

    // Fuzz TIFFSwabArrayOfFloat
    if (n > 0) {
        TIFFSwabArrayOfFloat(swabArray, n);
    }

    // Prepare data for TIFFCIELabToXYZ and TIFFXYZToRGB
    TIFFCIELabToRGB cielabToRGB;
    uint32_t L = dataCopy[0];
    int32_t a = dataCopy[1];
    int32_t b = dataCopy[2];
    float X, Y, Z;
    uint32_t R, G, B;

    // Fuzz TIFFCIELabToXYZ
    TIFFCIELabToXYZ(&cielabToRGB, L, a, b, &X, &Y, &Z);

    // Fuzz TIFFXYZToRGB
    TIFFXYZToRGB(&cielabToRGB, X, Y, Z, &R, &G, &B);

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

        LLVMFuzzerTestOneInput_51(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    