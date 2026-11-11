// This fuzz driver is generated for library liblouis, aiming to fuzz the following functions:
// lou_setDataPath at compileTranslationTable.c:59:1 in liblouis.h
// lou_compileString at compileTranslationTable.c:5430:1 in liblouis.h
// lou_listTables at metadata.c:1172:1 in liblouis.h
// lou_freeTableFiles at compileTranslationTable.c:4933:1 in liblouis.h
// lou_getTypeformForEmphClass at compileTranslationTable.c:5244:1 in liblouis.h
// lou_getEmphClasses at compileTranslationTable.c:5070:1 in liblouis.h
// lou_listTables at metadata.c:1172:1 in liblouis.h
// lou_freeTableFiles at compileTranslationTable.c:4933:1 in liblouis.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <liblouis.h>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cstdio>

#define MAXSTRING 1024

static void fuzz_lou_setDataPath(const uint8_t *Data, size_t Size) {
    if (Size > MAXSTRING - 1) return;
    char path[MAXSTRING];
    memcpy(path, Data, Size);
    path[Size] = '\0';
    lou_setDataPath(path);
}

static void fuzz_lou_compileString(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;
    size_t split = Size / 2;
    char tableList[MAXSTRING];
    char inString[MAXSTRING];
    memcpy(tableList, Data, split);
    tableList[split] = '\0';
    memcpy(inString, Data + split, Size - split);
    inString[Size - split] = '\0';

    // Check if tableList and inString are not empty to avoid segmentation fault
    if (tableList[0] != '\0' && inString[0] != '\0') {
        lou_compileString(tableList, inString);
    }
}

static void fuzz_lou_freeTableFiles() {
    char **tables = lou_listTables();
    if (tables) {
        lou_freeTableFiles(tables);
    }
}

static void fuzz_lou_getTypeformForEmphClass(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;
    size_t split = Size / 2;
    char tableList[MAXSTRING];
    char emphClass[MAXSTRING];
    memcpy(tableList, Data, split);
    tableList[split] = '\0';
    memcpy(emphClass, Data + split, Size - split);
    emphClass[Size - split] = '\0';

    // Check if tableList and emphClass are not empty to avoid segmentation fault
    if (tableList[0] != '\0' && emphClass[0] != '\0') {
        lou_getTypeformForEmphClass(tableList, emphClass);
    }
}

static void fuzz_lou_getEmphClasses(const uint8_t *Data, size_t Size) {
    if (Size > MAXSTRING - 1) return;
    char tableList[MAXSTRING];
    memcpy(tableList, Data, Size);
    tableList[Size] = '\0';

    // Check if tableList is not empty to avoid segmentation fault
    if (tableList[0] != '\0') {
        char const **classes = lou_getEmphClasses(tableList);
        if (classes) {
            for (int i = 0; classes[i] != NULL; ++i) {
                free((void *)classes[i]);
            }
            free(classes);
        }
    }
}

static void fuzz_lou_listTables() {
    char **tables = lou_listTables();
    if (tables) {
        lou_freeTableFiles(tables);
    }
}

extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size) {
    fuzz_lou_setDataPath(Data, Size);
    fuzz_lou_compileString(Data, Size);
    fuzz_lou_freeTableFiles();
    fuzz_lou_getTypeformForEmphClass(Data, Size);
    fuzz_lou_getEmphClasses(Data, Size);
    fuzz_lou_listTables();
    return 0;
}