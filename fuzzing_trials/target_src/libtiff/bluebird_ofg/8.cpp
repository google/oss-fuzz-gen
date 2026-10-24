#include <sys/stat.h>
#include <string.h>
#include "cstdint"
#include "cstring"  // Include for memcpy

extern "C" {
    #include "tiffio.h"
}

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    // Ensure there is enough data to create a TIFFFieldInfo object
    if (size < sizeof(TIFFFieldInfo)) {
        return 0;
    }

    // Create a TIFF object
    TIFF *tiff = TIFFOpen("dummy.tiff", "w");
    if (tiff == nullptr) {
        return 0;
    }

    // Create a TIFFFieldInfo object from the input data
    TIFFFieldInfo fieldInfo;
    memcpy(&fieldInfo, data, sizeof(TIFFFieldInfo));

    // Ensure the field name is null-terminated
    char fieldName[32];
    size_t nameLen = sizeof(fieldName) - 1 < size - sizeof(TIFFFieldInfo) ? sizeof(fieldName) - 1 : size - sizeof(TIFFFieldInfo);
    memcpy(fieldName, data + sizeof(TIFFFieldInfo), nameLen);
    fieldName[nameLen] = '\0';
    fieldInfo.field_name = fieldName;

    // Call the function-under-test
    TIFFMergeFieldInfo(tiff, &fieldInfo, 1);

    // Clean up
    TIFFClose(tiff);

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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
