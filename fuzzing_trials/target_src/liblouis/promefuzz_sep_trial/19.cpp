// This fuzz driver is generated for library liblouis, aiming to fuzz the following functions:
// lou_setDataPath at compileTranslationTable.c:59:1 in liblouis.h
// lou_listTables at metadata.c:1172:1 in liblouis.h
// lou_freeTableFiles at compileTranslationTable.c:4933:1 in liblouis.h
// lou_getTypeformForEmphClass at compileTranslationTable.c:5244:1 in liblouis.h
// lou_getEmphClasses at compileTranslationTable.c:5070:1 in liblouis.h
// lou_freeTableFiles at compileTranslationTable.c:4933:1 in liblouis.h
// lou_compileString at compileTranslationTable.c:5430:1 in liblouis.h
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
#include <cstdlib>
#include <cstring>
#include <fstream>

static void fuzz_lou_setDataPath(const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        char *path = new char[Size + 1];
        memcpy(path, Data, Size);
        path[Size] = '\0';
        lou_setDataPath(path);
        delete[] path;
    }
}

static void fuzz_lou_listTables() {
    char **tables = lou_listTables();
    if (tables) {
        lou_freeTableFiles(tables);
    }
}

static void fuzz_lou_getTypeformForEmphClass(const uint8_t *Data, size_t Size) {
    if (Size > 1) {
        size_t mid = Size / 2;
        char *tableList = new char[mid + 1];
        char *emphClass = new char[Size - mid + 1];
        memcpy(tableList, Data, mid);
        tableList[mid] = '\0';
        memcpy(emphClass, Data + mid, Size - mid);
        emphClass[Size - mid] = '\0';
        lou_getTypeformForEmphClass(tableList, emphClass);
        delete[] tableList;
        delete[] emphClass;
    }
}

static void fuzz_lou_getEmphClasses(const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        char *tableList = new char[Size + 1];
        memcpy(tableList, Data, Size);
        tableList[Size] = '\0';
        char const **classes = lou_getEmphClasses(tableList);
        if (classes) {
            lou_freeTableFiles(const_cast<char **>(classes));
        }
        delete[] tableList;
    }
}

static void fuzz_lou_compileString(const uint8_t *Data, size_t Size) {
    if (Size > 1) {
        size_t mid = Size / 2;
        char *tableList = new char[mid + 1];
        char *inString = new char[Size - mid + 1];
        memcpy(tableList, Data, mid);
        tableList[mid] = '\0';
        memcpy(inString, Data + mid, Size - mid);
        inString[Size - mid] = '\0';
        lou_compileString(tableList, inString);
        delete[] tableList;
        delete[] inString;
    }
}

extern "C" int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    fuzz_lou_setDataPath(Data, Size);
    fuzz_lou_listTables();
    fuzz_lou_getTypeformForEmphClass(Data, Size);
    fuzz_lou_getEmphClasses(Data, Size);
    fuzz_lou_compileString(Data, Size);
    return 0;
}