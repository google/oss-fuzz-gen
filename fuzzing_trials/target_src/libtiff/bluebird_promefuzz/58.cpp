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
#include <fstream>

static void WriteDummyFile(const uint8_t *Data, size_t Size) {
    std::ofstream file("./dummy_file", std::ios::binary);
    if (file.is_open()) {
        file.write(reinterpret_cast<const char*>(Data), Size);
        file.close();
    }
}

extern "C" int LLVMFuzzerTestOneInput_58(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy TIFF structure
    TIFF* tif = TIFFOpen("./dummy_file", "w");
    if (!tif) return 0;

    // Write the dummy file
    WriteDummyFile(Data, Size);

    // Ensure null-terminated string for fieldName
    std::vector<char> fieldNameBuffer(Data, Data + Size);
    fieldNameBuffer.push_back('\0');
    const char* fieldName = fieldNameBuffer.data();

    // Prepare data for testing
    void* clientData = const_cast<uint8_t*>(Data);
    const char* clientName = "client_info";

    // Test TIFFFieldWithName
    const TIFFField* field = TIFFFieldWithName(tif, fieldName);

    // Test TIFFSetClientInfo
    TIFFSetClientInfo(tif, clientData, clientName);

    // Test TIFFGetClientInfo
    void* retrievedClientData = TIFFGetClientInfo(tif, clientName);

    // Test TIFFSetFileName
    const char* prevFileName = TIFFSetFileName(tif, "./dummy_file");

    // Test TIFFFileName
    const char* fileName = TIFFFileName(tif);

    // Test TIFFClientdata
    thandle_t clientDataHandle = TIFFClientdata(tif);

    // Cleanup
    TIFFClose(tif);

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

    LLVMFuzzerTestOneInput_58(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
