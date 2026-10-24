// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFSwabDouble at tif_swab.c:201:6 in tiffio.h
// TIFFSwabArrayOfDouble at tif_swab.c:222:6 in tiffio.h
// uv_decode at tif_luv.c:997:5 in tiffio.h
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFIsByteSwapped at tif_open.c:889:5 in tiffio.h
// TIFFIsBigEndian at tif_open.c:904:5 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
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

extern "C" int LLVMFuzzerTestOneInput_121(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double) * 2 + sizeof(int)) {
        return 0; // Not enough data for meaningful fuzzing
    }

    // Fuzzing TIFFSwabDouble
    double value;
    memcpy(&value, Data, sizeof(double));
    TIFFSwabDouble(&value);

    // Fuzzing TIFFSwabArrayOfDouble
    tmsize_t numDoubles = static_cast<tmsize_t>(Size / sizeof(double));
    double *doubleArray = static_cast<double *>(malloc(numDoubles * sizeof(double)));
    if (doubleArray) {
        memcpy(doubleArray, Data, numDoubles * sizeof(double));
        TIFFSwabArrayOfDouble(doubleArray, numDoubles);
        free(doubleArray);
    }

    // Fuzzing uv_encode
    double latitude, longitude;
    memcpy(&latitude, Data, sizeof(double));
    memcpy(&longitude, Data + sizeof(double), sizeof(double));
    int precision = *reinterpret_cast<const int *>(Data + sizeof(double) * 2);
    uv_encode(latitude, longitude, precision);

    // Fuzzing uv_decode
    int numCoordinates = precision; // Using precision as a proxy for number of coordinates
    if (numCoordinates > 0 && Size >= numCoordinates * sizeof(double)) {
        double *inputData = static_cast<double *>(malloc(numCoordinates * sizeof(double)));
        double *u = static_cast<double *>(malloc(numCoordinates * sizeof(double)));
        double *v = static_cast<double *>(malloc(numCoordinates * sizeof(double)));
        if (inputData && u && v) {
            memcpy(inputData, Data, numCoordinates * sizeof(double));
            uv_decode(inputData, u, numCoordinates);
            free(inputData);
            free(u);
            free(v);
        } else {
            free(inputData);
            free(u);
            free(v);
        }
    }

    // Fuzzing TIFFIsByteSwapped and TIFFIsBigEndian
    TIFF *tiff = TIFFOpen("./dummy_file", "r");
    if (tiff) {
        TIFFIsByteSwapped(tiff);
        TIFFIsBigEndian(tiff);
        TIFFClose(tiff);
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

        LLVMFuzzerTestOneInput_121(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    