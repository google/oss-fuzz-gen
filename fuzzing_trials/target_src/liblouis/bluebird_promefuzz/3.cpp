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
#include "../../liblouis/liblouis.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cstdio>

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Prepare a null-terminated string from the input data
    char *inputStr = static_cast<char *>(malloc(Size + 1));
    if (!inputStr) {
        return 0;
    }
    memcpy(inputStr, Data, Size);
    inputStr[Size] = '\0';

    // 1. Test lou_setDataPath
    lou_setDataPath(inputStr);

    // 2. Test lou_indexTables
    const char *tables[] = {inputStr, nullptr};
    lou_indexTables(tables);

    // 3. Test lou_getTableInfo
    lou_getTableInfo(inputStr, inputStr);

    // 4. Test lou_readCharFromFile
    FILE *dummyFile = fopen("./dummy_file", "wb");
    if (dummyFile) {
        fwrite(Data, 1, Size, dummyFile);
        fclose(dummyFile);

        int mode = 0;
        int htoafssi = Size;
        // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of lou_readCharFromFile
        lou_readCharFromFile("./dummy_file", &htoafssi);
        // End mutation: Producer.REPLACE_ARG_MUTATOR
    }

    // 5. Test lou_findTable
    char *bestMatch = lou_findTable(inputStr);
    if (bestMatch) {
        free(bestMatch);
    }

    // 6. Test lou_findTables
    char **matchingTables = lou_findTables(inputStr);
    if (matchingTables) {
        for (char **table = matchingTables; *table != nullptr; ++table) {
            free(*table);
        }
        free(matchingTables);
    }

    free(inputStr);
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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
