#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include "sstream"
#include <string>
#include <vector>
#include "cstring"
#include "cstdlib"
#include <cstdio>
#include "cstdint"
#include <cstddef>
#include "tiffio.h"
#include "cstdint"
#include "cstdlib"
#include "cstring"
#include <cstdio>

static TIFF* createDummyTIFF() {
    FILE* file = fopen("./dummy_file", "wb+");
    if (!file) {
        return nullptr;
    }
    fclose(file);
    return TIFFOpen("./dummy_file", "r+");
}

extern "C" int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    TIFF* tif = createDummyTIFF();
    if (!tif) return 0;

    // Use a portion of the input data as a string
    size_t strLen = Size < 256 ? Size : 255;
    char fieldName[256];
    memcpy(fieldName, Data, strLen);
    fieldName[strLen] = '\0';

    // Fuzz TIFFFieldWithName
    const TIFFField* field = TIFFFieldWithName(tif, fieldName);

    // Fuzz TIFFSetClientInfo
    void* clientData = malloc(Size);
    if (clientData) {
        memcpy(clientData, Data, Size);
        TIFFSetClientInfo(tif, clientData, fieldName);

        // Fuzz TIFFGetClientInfo
        void* retrievedData = TIFFGetClientInfo(tif, fieldName);
        if (retrievedData) {
            // Do something with retrievedData (no-op in this case)
        }

        // Clean up client data
        free(clientData);
    }

    // Fuzz TIFFSetClientdata and TIFFClientdata
    thandle_t oldClientData = TIFFSetClientdata(tif, const_cast<thandle_t>(reinterpret_cast<const void*>(Data)));
    thandle_t currentClientData = TIFFClientdata(tif);

    // Clean up TIFF structure
    TIFFCleanup(tif);

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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
