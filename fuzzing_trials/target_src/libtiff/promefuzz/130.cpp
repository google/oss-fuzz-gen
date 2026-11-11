// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFSwabDouble at tif_swab.c:201:6 in tiffio.h
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFIsByteSwapped at tif_open.c:889:5 in tiffio.h
// TIFFIsBigEndian at tif_open.c:904:5 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFSwabArrayOfDouble at tif_swab.c:222:6 in tiffio.h
// uv_decode at tif_luv.c:997:5 in tiffio.h
// uv_decode at tif_luv.c:997:5 in tiffio.h
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
#include "tiffio.h"

extern "C" int LLVMFuzzerTestOneInput_130(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double) * 2 + sizeof(int)) {
        return 0; // Not enough data to proceed
    }

    // Prepare a double for TIFFSwabDouble
    double swabDouble;
    memcpy(&swabDouble, Data, sizeof(double));
    TIFFSwabDouble(&swabDouble);

    // Prepare a TIFF structure for TIFFIsByteSwapped and TIFFIsBigEndian
    TIFF *tiff = TIFFOpen("./dummy_file", "w");
    if (tiff) {
        TIFFIsByteSwapped(tiff);
        TIFFIsBigEndian(tiff);
        TIFFClose(tiff);
    }

    // Prepare doubles for uv_encode
    double latitude, longitude;
    int precision;
    memcpy(&latitude, Data, sizeof(double));
    memcpy(&longitude, Data + sizeof(double), sizeof(double));
    memcpy(&precision, Data + 2 * sizeof(double), sizeof(int));
    uv_encode(latitude, longitude, precision);

    // Prepare an array for TIFFSwabArrayOfDouble
    if (Size >= sizeof(double) * 4) {
        double arrayOfDoubles[2];
        memcpy(arrayOfDoubles, Data, sizeof(double) * 2);
        TIFFSwabArrayOfDouble(arrayOfDoubles, 2);
    }

    // Prepare buffers for uv_decode
    if (Size >= sizeof(double) * 4) {
        double inputArray[2];
        memcpy(inputArray, Data, sizeof(double) * 2);
        double u[2], v[2];
        uv_decode(inputArray, u, 2);
        uv_decode(inputArray, v, 2);
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

        LLVMFuzzerTestOneInput_130(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    