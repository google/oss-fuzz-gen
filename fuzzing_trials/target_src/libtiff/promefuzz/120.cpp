// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFSwabDouble at tif_swab.c:201:6 in tiffio.h
// TIFFSwabArrayOfDouble at tif_swab.c:222:6 in tiffio.h
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFIsByteSwapped at tif_open.c:889:5 in tiffio.h
// TIFFIsBigEndian at tif_open.c:904:5 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
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
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_120(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double)) {
        return 0; // Not enough data to form a double
    }

    // Test TIFFSwabDouble
    double dbl;
    memcpy(&dbl, Data, sizeof(double));
    TIFFSwabDouble(&dbl);

    // Test TIFFSwabArrayOfDouble
    if (Size >= 2 * sizeof(double)) {
        double dblArray[2];
        memcpy(dblArray, Data, 2 * sizeof(double));
        TIFFSwabArrayOfDouble(dblArray, 2);
    }

    // Create a dummy TIFF structure
    TIFF *tiff = TIFFOpen("./dummy_file", "w");
    if (tiff) {
        // Test TIFFIsByteSwapped
        int isByteSwapped = TIFFIsByteSwapped(tiff);

        // Test TIFFIsBigEndian
        int isBigEndian = TIFFIsBigEndian(tiff);

        TIFFClose(tiff);
    }

    // Test uv_encode
    if (Size >= 2 * sizeof(double) + sizeof(int)) {
        double lat, lon;
        int precision;
        memcpy(&lat, Data, sizeof(double));
        memcpy(&lon, Data + sizeof(double), sizeof(double));
        memcpy(&precision, Data + 2 * sizeof(double), sizeof(int));
        int encoded = uv_encode(lat, lon, precision);
    }

    // Test uv_decode
    if (Size >= sizeof(double) * 2 + sizeof(int)) {
        double u, v;
        int count;
        memcpy(&count, Data + sizeof(double) * 2, sizeof(int));
        if (count > 0) {
            std::vector<double> inputData(count);
            memcpy(inputData.data(), Data, sizeof(double) * count);
            uv_decode(inputData.data(), &u, count);
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

        LLVMFuzzerTestOneInput_120(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    