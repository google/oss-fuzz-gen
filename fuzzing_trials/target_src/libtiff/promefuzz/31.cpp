// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFSwabDouble at tif_swab.c:201:6 in tiffio.h
// TIFFIsByteSwapped at tif_open.c:889:5 in tiffio.h
// TIFFIsBigEndian at tif_open.c:904:5 in tiffio.h
// uv_decode at tif_luv.c:997:5 in tiffio.h
// TIFFSwabArrayOfDouble at tif_swab.c:222:6 in tiffio.h
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
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
#include <tiffio.h>

static void fuzz_TIFFSwabDouble(double *value) {
    TIFFSwabDouble(value);
}

static int fuzz_TIFFIsByteSwapped(TIFF *tiff) {
    return TIFFIsByteSwapped(tiff);
}

static int fuzz_TIFFIsBigEndian(TIFF *tiff) {
    return TIFFIsBigEndian(tiff);
}

static int fuzz_uv_encode(double lat, double lon, int precision) {
    return uv_encode(lat, lon, precision);
}

static int fuzz_uv_decode(double *input, int count) {
    double outputU[count];
    double outputV[count];
    return uv_decode(input, outputU, count);
}

static void fuzz_TIFFSwabArrayOfDouble(double *array, tmsize_t n) {
    TIFFSwabArrayOfDouble(array, n);
}

extern "C" int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double)) return 0;

    // Fuzz TIFFSwabDouble
    double value;
    memcpy(&value, Data, sizeof(double));
    fuzz_TIFFSwabDouble(&value);

    // Fuzz TIFFIsByteSwapped and TIFFIsBigEndian
    TIFF *tiff = TIFFOpen("./dummy_file", "w");
    if (tiff) {
        fuzz_TIFFIsByteSwapped(tiff);
        fuzz_TIFFIsBigEndian(tiff);
        TIFFClose(tiff);
    }

    // Fuzz uv_encode
    if (Size >= 2 * sizeof(double) + sizeof(int)) {
        double lat, lon;
        int precision;
        memcpy(&lat, Data, sizeof(double));
        memcpy(&lon, Data + sizeof(double), sizeof(double));
        memcpy(&precision, Data + 2 * sizeof(double), sizeof(int));
        fuzz_uv_encode(lat, lon, precision);
    }

    // Fuzz uv_decode
    if (Size >= 2 * sizeof(double)) {
        double input[2];
        memcpy(input, Data, 2 * sizeof(double));
        fuzz_uv_decode(input, 2);
    }

    // Fuzz TIFFSwabArrayOfDouble
    if (Size >= sizeof(double)) {
        fuzz_TIFFSwabArrayOfDouble(&value, 1);
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

        LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    