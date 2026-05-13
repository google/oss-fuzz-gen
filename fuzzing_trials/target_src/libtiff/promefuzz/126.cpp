// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFSwabDouble at tif_swab.c:201:6 in tiffio.h
// TIFFIsByteSwapped at tif_open.c:889:5 in tiffio.h
// TIFFIsBigEndian at tif_open.c:904:5 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
// uv_decode at tif_luv.c:997:5 in tiffio.h
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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <tiffio.h>

static TIFF* createDummyTIFF() {
    FILE* file = fopen("./dummy_file", "wb+");
    if (!file) return nullptr;
    fclose(file);
    return TIFFOpen("./dummy_file", "r+");
}

extern "C" int LLVMFuzzerTestOneInput_126(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double) * 2 + sizeof(int)) return 0;

    double doubleValue;
    double latitude, longitude;
    int precision;
    memcpy(&doubleValue, Data, sizeof(double));
    memcpy(&latitude, Data, sizeof(double));
    memcpy(&longitude, Data + sizeof(double), sizeof(double));
    memcpy(&precision, Data + sizeof(double) * 2, sizeof(int));

    TIFFSwabDouble(&doubleValue);

    TIFF* tiff = createDummyTIFF();
    if (tiff) {
        TIFFIsByteSwapped(tiff);
        TIFFIsBigEndian(tiff);
        TIFFClose(tiff);
    }

    uv_encode(latitude, longitude, precision);

    if (Size >= sizeof(double) * 3 + sizeof(int)) {
        double inputArray[2];
        double outputU[2], outputV[2];
        int count;
        memcpy(inputArray, Data, sizeof(double) * 2);
        memcpy(&count, Data + sizeof(double) * 2, sizeof(int));

        uv_decode(inputArray, outputU, count);
    }

    if (Size >= sizeof(double) * 3) {
        double doubleArray[3];
        memcpy(doubleArray, Data, sizeof(double) * 3);
        TIFFSwabArrayOfDouble(doubleArray, 3);
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

        LLVMFuzzerTestOneInput_126(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    