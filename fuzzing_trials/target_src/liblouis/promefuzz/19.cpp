// This fuzz driver is generated for library liblouis, aiming to fuzz the following functions:
// lou_compileString at compileTranslationTable.c:5446:1 in liblouis.h
// lou_getTable at compileTranslationTable.c:5134:1 in liblouis.h
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
#include <liblouis.h>

static void fuzz_lou_compileString(const uint8_t *Data, size_t Size) {
    if (Size < 2) return; // Ensure there's enough data for at least tableList and inString
    const char *tableList = reinterpret_cast<const char*>(Data);
    size_t tableListLen = strnlen(tableList, Size);
    if (tableListLen >= Size) return; // Ensure null-terminated within bounds
    const char *inString = reinterpret_cast<const char*>(Data + tableListLen + 1);
    size_t inStringLen = strnlen(inString, Size - tableListLen - 1);
    if (tableListLen + inStringLen + 2 > Size) return; // Ensure both strings are null-terminated within bounds
    if (tableListLen == 0 || inStringLen == 0) return; // Ensure non-empty strings
    lou_compileString(tableList, inString);
}

static void fuzz_lou_getTable(const uint8_t *Data, size_t Size) {
    if (Size < 1) return; // Ensure there's enough data for at least tableList
    const char *tableList = reinterpret_cast<const char*>(Data);
    size_t tableListLen = strnlen(tableList, Size);
    if (tableListLen >= Size) return; // Ensure null-terminated within bounds
    if (tableListLen == 0) return; // Ensure non-empty string
    lou_getTable(tableList);
}

static void fuzz_lou_getEmphClasses(const uint8_t *Data, size_t Size) {
    if (Size < 1) return; // Ensure there's enough data for at least tableList
    const char *tableList = reinterpret_cast<const char*>(Data);
    size_t tableListLen = strnlen(tableList, Size);
    if (tableListLen >= Size) return; // Ensure null-terminated within bounds
    if (tableListLen == 0) return; // Ensure non-empty string
    char const **emphClasses = lou_getEmphClasses(tableList);
    if (emphClasses) {
        for (int i = 0; emphClasses[i] != nullptr; ++i) {
            free((void*)emphClasses[i]);
        }
        free(emphClasses);
    }
}

static void fuzz_lou_getTypeformForEmphClass(const uint8_t *Data, size_t Size) {
    if (Size < 2) return; // Ensure there's enough data for at least tableList and emphClass
    const char *tableList = reinterpret_cast<const char*>(Data);
    size_t tableListLen = strnlen(tableList, Size);
    if (tableListLen >= Size) return; // Ensure null-terminated within bounds
    const char *emphClass = reinterpret_cast<const char*>(Data + tableListLen + 1);
    size_t emphClassLen = strnlen(emphClass, Size - tableListLen - 1);
    if (tableListLen + emphClassLen + 2 > Size) return; // Ensure both strings are null-terminated within bounds
    if (tableListLen == 0 || emphClassLen == 0) return; // Ensure non-empty strings
    lou_getTypeformForEmphClass(tableList, emphClass);
}

static void fuzz_lou_findTable(const uint8_t *Data, size_t Size) {
    if (Size < 1) return; // Ensure there's enough data for at least query
    const char *query = reinterpret_cast<const char*>(Data);
    size_t queryLen = strnlen(query, Size);
    if (queryLen >= Size) return; // Ensure null-terminated within bounds
    if (queryLen == 0) return; // Ensure non-empty string
    char *result = lou_findTable(query);
    if (result) {
        free(result);
    }
}

static void fuzz_lou_findTables(const uint8_t *Data, size_t Size) {
    if (Size < 1) return; // Ensure there's enough data for at least query
    const char *query = reinterpret_cast<const char*>(Data);
    size_t queryLen = strnlen(query, Size);
    if (queryLen >= Size) return; // Ensure null-terminated within bounds
    if (queryLen == 0) return; // Ensure non-empty string
    char **results = lou_findTables(query);
    if (results) {
        for (int i = 0; results[i] != nullptr; ++i) {
            free(results[i]);
        }
        free(results);
    }
}

extern "C" int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    fuzz_lou_compileString(Data, Size);
    fuzz_lou_getTable(Data, Size);
    fuzz_lou_getEmphClasses(Data, Size);
    fuzz_lou_getTypeformForEmphClass(Data, Size);
    fuzz_lou_findTable(Data, Size);
    fuzz_lou_findTables(Data, Size);
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

        LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    