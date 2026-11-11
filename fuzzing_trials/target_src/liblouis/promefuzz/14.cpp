// This fuzz driver is generated for library liblouis, aiming to fuzz the following functions:
// lou_getTable at compileTranslationTable.c:5134:1 in liblouis.h
// lou_compileString at compileTranslationTable.c:5446:1 in liblouis.h
// lou_getEmphClasses at compileTranslationTable.c:5086:1 in liblouis.h
// lou_getTypeformForEmphClass at compileTranslationTable.c:5260:1 in liblouis.h
// lou_findTable at metadata.c:1068:1 in liblouis.h
// lou_findTables at metadata.c:1115:1 in liblouis.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include "liblouis.h"

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0; // Ensure there's enough data for non-empty strings

    // Prepare input strings
    char *inputStr = (char *)malloc(Size + 1);
    if (!inputStr) return 0;
    memcpy(inputStr, Data, Size);
    inputStr[Size] = '\0';

    // Split the input into two parts for tableList and inString
    size_t mid = Size / 2;
    inputStr[mid] = '\0'; // Null-terminate the first part

    const char *tableList = inputStr;
    const char *inString = inputStr + mid + 1;

    // Use lou_getTable to ensure the table is valid before using it
    const void *table = lou_getTable(tableList);
    if (table) {
        // Use lou_compileString
        lou_compileString(tableList, inString);

        // Use lou_getEmphClasses
        char const **emphClasses = lou_getEmphClasses(tableList);
        if (emphClasses) {
            for (int i = 0; emphClasses[i] != NULL; ++i) {
                // Free each string in the array
                free((void *)emphClasses[i]);
            }
            free(emphClasses);
        }

        // Use lou_getTypeformForEmphClass
        lou_getTypeformForEmphClass(tableList, inString);

        // Use lou_findTable
        char *foundTable = lou_findTable(tableList);
        if (foundTable) {
            free(foundTable);
        }

        // Use lou_findTables
        char **foundTables = lou_findTables(tableList);
        if (foundTables) {
            for (int i = 0; foundTables[i] != NULL; ++i) {
                free(foundTables[i]);
            }
            free(foundTables);
        }
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

        LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    