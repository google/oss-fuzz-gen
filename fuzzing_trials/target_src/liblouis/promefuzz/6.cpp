// This fuzz driver is generated for library liblouis, aiming to fuzz the following functions:
// lou_checkTable at compileTranslationTable.c:5254:1 in liblouis.h
// lou_findTable at metadata.c:1068:1 in liblouis.h
// lou_indexTables at metadata.c:947:1 in liblouis.h
// lou_findTables at metadata.c:1115:1 in liblouis.h
// lou_listTables at metadata.c:1177:1 in liblouis.h
// lou_registerTableResolver at compileTranslationTable.c:4878:1 in liblouis.h
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
#include <cstdlib>
#include <cstring>
#include "liblouis.h"

extern "C" int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Convert fuzz data to a null-terminated string
    char *inputStr = static_cast<char *>(malloc(Size + 1));
    if (!inputStr) return 0;
    memcpy(inputStr, Data, Size);
    inputStr[Size] = '\0';

    // Fuzz lou_checkTable
    int checkTableResult = lou_checkTable(inputStr);

    // Fuzz lou_findTable
    char *foundTable = lou_findTable(inputStr);
    if (foundTable) {
        free(foundTable);
    }

    // Fuzz lou_indexTables
    const char *tables[] = {inputStr, nullptr};
    lou_indexTables(tables);

    // Fuzz lou_findTables
    char **foundTables = lou_findTables(inputStr);
    if (foundTables) {
        for (char **table = foundTables; *table != nullptr; ++table) {
            free(*table);
        }
        free(foundTables);
    }

    // Fuzz lou_listTables
    char **listTables = lou_listTables();
    if (listTables) {
        for (char **table = listTables; *table != nullptr; ++table) {
            free(*table);
        }
        free(listTables);
    }

    // Fuzz lou_registerTableResolver with a dummy resolver
    lou_registerTableResolver(nullptr);

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

        LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    