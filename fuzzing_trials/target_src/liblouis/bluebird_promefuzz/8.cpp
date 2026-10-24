#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <iostream>
#include <fstream>
#include "../../liblouis/liblouis.h"
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Ensure null-termination for dataPath
    char *dataPath = new char[Size + 1];
    memcpy(dataPath, Data, Size);
    dataPath[Size] = '\0';
    lou_setDataPath(dataPath);
    delete[] dataPath;

    // Prepare data for lou_compileString
    if (Size > 2) {
        size_t mid = Size / 2;
        char *tableList = new char[mid + 1];
        char *inString = new char[Size - mid + 1];
        memcpy(tableList, Data, mid);
        memcpy(inString, Data + mid, Size - mid);
        tableList[mid] = '\0';
        inString[Size - mid] = '\0';

        // Ensure both tableList and inString are non-empty
        if (tableList[0] != '\0' && inString[0] != '\0') {
            lou_compileString(tableList, inString);
        }

        delete[] tableList;
        delete[] inString;
    }

    // Prepare data for lou_charToDots
    if (Size > 3) {
        char *tableList = new char[Size];
        widechar *inbuf = new widechar[Size / 2];
        widechar outbuf[256] = {0};
        memcpy(tableList, Data, Size - 2);
        memcpy(inbuf, Data + 1, (Size - 2) / 2);
        tableList[Size - 2] = '\0';
        int length = static_cast<int>((Size - 2) / 2);
        int mode = static_cast<int>(Data[Size - 1]);
        lou_charToDots(tableList, inbuf, outbuf, length, mode);
        delete[] tableList;
        delete[] inbuf;
    }

    // Prepare data for lou_readCharFromFile
    std::ofstream dummyFile("./dummy_file");
    if (dummyFile.is_open()) {
        dummyFile.write(reinterpret_cast<const char*>(Data), Size);
        dummyFile.close();

        int mode = 0;
        lou_readCharFromFile("./dummy_file", &mode);
    }

    // Prepare data for lou_backTranslateString
    if (Size > 4) {
        char *tableList = new char[Size];
        widechar *inbuf = new widechar[Size / 2];
        widechar outbuf[256] = {0};
        memcpy(tableList, Data, Size - 2);
        memcpy(inbuf, Data + 1, (Size - 2) / 2);
        tableList[Size - 2] = '\0';
        int inlen = static_cast<int>((Size - 2) / 2);
        int outlen = 256;
        // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of lou_backTranslateString
        lou_backTranslateString(tableList, inbuf, NULL, outbuf, &outlen, NULL, NULL, 0);
        // End mutation: Producer.REPLACE_ARG_MUTATOR
        delete[] tableList;
        delete[] inbuf;
    }

    // Call lou_charSize
    lou_charSize();

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
