// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// TIFFSwabDouble at tif_swab.c:201:6 in tiffio.h
// TIFFSwabArrayOfDouble at tif_swab.c:222:6 in tiffio.h
// TIFFIsByteSwapped at tif_open.c:889:5 in tiffio.h
// TIFFIsBigEndian at tif_open.c:904:5 in tiffio.h
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
#include <tiffio.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static TIFF* openDummyTIFF() {
    FILE* file = fopen("./dummy_file", "wb+");
    if (!file) return nullptr;

    // Write a minimal valid TIFF header to the file
    const unsigned char header[] = { 'I', 'I', 42, 0, 8, 0, 0, 0 };
    fwrite(header, sizeof(header), 1, file);
    fclose(file);

    return TIFFOpen("./dummy_file", "r+");
}

static void closeDummyTIFF(TIFF* tiff) {
    if (tiff) {
        TIFFClose(tiff);
        remove("./dummy_file");
    }
}

extern "C" int LLVMFuzzerTestOneInput_113(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double)) return 0;

    // Fuzz TIFFSwabDouble
    double value;
    memcpy(&value, Data, sizeof(double));
    TIFFSwabDouble(&value);

    // Fuzz TIFFSwabArrayOfDouble
    if (Size >= 2 * sizeof(double)) {
        double array[2];
        memcpy(array, Data, 2 * sizeof(double));
        TIFFSwabArrayOfDouble(array, 2);
    }

    // Fuzz TIFFIsByteSwapped and TIFFIsBigEndian
    TIFF* tiff = openDummyTIFF();
    if (tiff) {
        TIFFIsByteSwapped(tiff);
        TIFFIsBigEndian(tiff);
        closeDummyTIFF(tiff);
    }

    // Fuzz uv_encode
    if (Size >= 2 * sizeof(double) + sizeof(int)) {
        double lat, lon;
        int precision;
        memcpy(&lat, Data, sizeof(double));
        memcpy(&lon, Data + sizeof(double), sizeof(double));
        memcpy(&precision, Data + 2 * sizeof(double), sizeof(int));
        uv_encode(lat, lon, precision);
    }

    // Fuzz uv_decode
    if (Size >= sizeof(double)) {
        // Ensure the inputBuffer size does not exceed the actual data size
        size_t numDoubles = Size / sizeof(double);
        std::vector<double> inputBuffer(numDoubles);
        memcpy(inputBuffer.data(), Data, numDoubles * sizeof(double));

        double u, v;
        uv_decode(inputBuffer.data(), &u, static_cast<int>(numDoubles));
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

        LLVMFuzzerTestOneInput_113(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    