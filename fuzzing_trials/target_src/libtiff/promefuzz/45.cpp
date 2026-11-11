// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFSwabLong8 at tif_swab.c:60:6 in tiffio.h
// TIFFSwabArrayOfTriples at tif_swab.c:99:6 in tiffio.h
// TIFFSwabArrayOfShort at tif_swab.c:81:6 in tiffio.h
// TIFFSwabArrayOfLong at tif_swab.c:117:6 in tiffio.h
// TIFFSwabArrayOfLong8 at tif_swab.c:138:6 in tiffio.h
// TIFFSwabArrayOfDouble at tif_swab.c:222:6 in tiffio.h
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
#include <cstdlib>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_45(const uint8_t *Data, size_t Size) {
    if (Size < 8) return 0; // Ensure there's enough data for at least one 64-bit integer

    // Test TIFFSwabLong8
    uint64_t long8Value;
    memcpy(&long8Value, Data, sizeof(uint64_t));
    TIFFSwabLong8(&long8Value);

    // Test TIFFSwabArrayOfTriples
    if (Size >= 3) {
        uint8_t *triplesData = (uint8_t *)malloc(Size);
        if (triplesData) {
            memcpy(triplesData, Data, Size);
            tmsize_t numTriples = Size / 3;
            TIFFSwabArrayOfTriples(triplesData, numTriples);
            free(triplesData);
        }
    }

    // Test TIFFSwabArrayOfShort
    if (Size >= sizeof(uint16_t)) {
        tmsize_t numShorts = Size / sizeof(uint16_t);
        uint16_t *shortArray = (uint16_t *)malloc(numShorts * sizeof(uint16_t));
        if (shortArray) {
            memcpy(shortArray, Data, numShorts * sizeof(uint16_t));
            TIFFSwabArrayOfShort(shortArray, numShorts);
            free(shortArray);
        }
    }

    // Test TIFFSwabArrayOfLong
    if (Size >= sizeof(uint32_t)) {
        tmsize_t numLongs = Size / sizeof(uint32_t);
        uint32_t *longArray = (uint32_t *)malloc(numLongs * sizeof(uint32_t));
        if (longArray) {
            memcpy(longArray, Data, numLongs * sizeof(uint32_t));
            TIFFSwabArrayOfLong(longArray, numLongs);
            free(longArray);
        }
    }

    // Test TIFFSwabArrayOfLong8
    if (Size >= sizeof(uint64_t)) {
        tmsize_t numLong8s = Size / sizeof(uint64_t);
        uint64_t *long8Array = (uint64_t *)malloc(numLong8s * sizeof(uint64_t));
        if (long8Array) {
            memcpy(long8Array, Data, numLong8s * sizeof(uint64_t));
            TIFFSwabArrayOfLong8(long8Array, numLong8s);
            free(long8Array);
        }
    }

    // Test TIFFSwabArrayOfDouble
    if (Size >= sizeof(double)) {
        tmsize_t numDoubles = Size / sizeof(double);
        double *doubleArray = (double *)malloc(numDoubles * sizeof(double));
        if (doubleArray) {
            memcpy(doubleArray, Data, numDoubles * sizeof(double));
            TIFFSwabArrayOfDouble(doubleArray, numDoubles);
            free(doubleArray);
        }
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

        LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    