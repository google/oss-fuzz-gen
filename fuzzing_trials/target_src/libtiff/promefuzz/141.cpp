// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFSwabDouble at tif_swab.c:201:6 in tiffio.h
// TIFFSwabArrayOfDouble at tif_swab.c:222:6 in tiffio.h
// uv_decode at tif_luv.c:997:5 in tiffio.h
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

extern "C" int LLVMFuzzerTestOneInput_141(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double)) return 0;

    // Fuzzing TIFFSwabDouble
    double value;
    memcpy(&value, Data, sizeof(double));
    TIFFSwabDouble(&value);

    // Fuzzing TIFFSwabArrayOfDouble
    size_t numDoubles = Size / sizeof(double);
    if (numDoubles > 0) {
        double *array = static_cast<double *>(malloc(numDoubles * sizeof(double)));
        if (array) {
            memcpy(array, Data, numDoubles * sizeof(double));
            TIFFSwabArrayOfDouble(array, numDoubles);
            free(array);
        }
    }

    // Fuzzing uv_encode
    if (Size >= 2 * sizeof(double) + sizeof(int)) {
        double lat, lon;
        int precision;
        memcpy(&lat, Data, sizeof(double));
        memcpy(&lon, Data + sizeof(double), sizeof(double));
        memcpy(&precision, Data + 2 * sizeof(double), sizeof(int));
        uv_encode(lat, lon, precision);
    }

    // Fuzzing uv_decode
    if (numDoubles > 0) {
        double *input = static_cast<double *>(malloc(numDoubles * sizeof(double)));
        double *u_output = static_cast<double *>(malloc(numDoubles * sizeof(double)));
        double *v_output = static_cast<double *>(malloc(numDoubles * sizeof(double)));
        if (input && u_output && v_output) {
            memcpy(input, Data, numDoubles * sizeof(double));
            uv_decode(input, u_output, numDoubles);
            uv_decode(input, v_output, numDoubles);
        }
        free(input);
        free(u_output);
        free(v_output);
    }

    // Writing data to a dummy file for TIFF functions
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);

        // Fuzzing TIFFIsByteSwapped and TIFFIsBigEndian
        TIFF *tiff = TIFFOpen("./dummy_file", "r");
        if (tiff) {
            TIFFIsByteSwapped(tiff);
            TIFFIsBigEndian(tiff);
            TIFFClose(tiff);
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

        LLVMFuzzerTestOneInput_141(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    