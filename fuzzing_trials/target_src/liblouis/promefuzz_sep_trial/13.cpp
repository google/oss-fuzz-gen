// This fuzz driver is generated for library liblouis, aiming to fuzz the following functions:
// lou_free at compileTranslationTable.c:5363:1 in liblouis.h
// lou_freeTableFile at metadata.c:1089:1 in liblouis.h
// lou_freeTableInfo at metadata.c:1167:1 in liblouis.h
// lou_freeEmphClasses at compileTranslationTable.c:5095:1 in liblouis.h
// lou_getEmphClasses at compileTranslationTable.c:5070:1 in liblouis.h
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
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <liblouis.h>

static void fuzzLouFree() {
    lou_free();
}

static void fuzzLouFreeTableFile(char *data) {
    lou_freeTableFile(data);
}

static void fuzzLouFreeTableInfo(char *data) {
    lou_freeTableInfo(data);
}

static void fuzzLouFreeEmphClasses(char const **data) {
    lou_freeEmphClasses(data);
}

static char const **fuzzLouGetEmphClasses(const char *tableList) {
    return lou_getEmphClasses(tableList);
}

static void fuzzLouFreeTableFiles(char **data) {
    lou_freeTableFiles(data);
}

extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Create a mutable copy of the input data
    char *mutableData = static_cast<char *>(malloc(Size + 1));
    if (!mutableData) return 0;
    memcpy(mutableData, Data, Size);
    mutableData[Size] = '\0';

    // Fuzz various functions
    fuzzLouFree();

    // Ensure we don't free the same data twice
    char *tableFileCopy = static_cast<char *>(malloc(Size + 1));
    if (tableFileCopy) {
        memcpy(tableFileCopy, Data, Size);
        tableFileCopy[Size] = '\0';
        fuzzLouFreeTableFile(tableFileCopy);
        // No need to free tableFileCopy since lou_freeTableFile already frees it
    }

    char *tableInfoCopy = static_cast<char *>(malloc(Size + 1));
    if (tableInfoCopy) {
        memcpy(tableInfoCopy, Data, Size);
        tableInfoCopy[Size] = '\0';
        fuzzLouFreeTableInfo(tableInfoCopy);
        // No need to free tableInfoCopy since lou_freeTableInfo already frees it
    }

    char const **emphClasses = fuzzLouGetEmphClasses(mutableData);
    if (emphClasses) {
        fuzzLouFreeEmphClasses(emphClasses);
    }

    char **tableFiles = reinterpret_cast<char **>(malloc(sizeof(char *) * 2));
    if (tableFiles) {
        tableFiles[0] = mutableData;
        tableFiles[1] = nullptr;
        fuzzLouFreeTableFiles(tableFiles);
        // No need to free tableFiles here, as it is freed in fuzzLouFreeTableFiles
    } else {
        free(mutableData);
    }

    return 0;
}