// This fuzz driver is generated for library liblouis, aiming to fuzz the following functions:
// lou_getTableInfo at metadata.c:1142:1 in liblouis.h
// lou_backTranslateString at lou_backTranslateString.c:152:1 in liblouis.h
// lou_translateString at lou_translateString.c:1128:1 in liblouis.h
// lou_checkTable at compileTranslationTable.c:5238:1 in liblouis.h
// lou_indexTables at metadata.c:945:1 in liblouis.h
// lou_findTable at metadata.c:1063:1 in liblouis.h
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
#include <iostream>
#include <fstream>

static void fuzz_lou_backTranslateString(const uint8_t *Data, size_t Size) {
    if (Size < 4) return; // Ensure there's enough data for basic use

    const char *tableList = "unicode.dis"; // Using a default table
    widechar inbuf[Size];
    int inlen = Size / sizeof(widechar);
    std::memcpy(inbuf, Data, inlen * sizeof(widechar));

    widechar outbuf[Size];
    int outlen = Size / sizeof(widechar);
    formtype *typeform = nullptr; // No typeform checking
    char *spacing = nullptr; // No spacing info
    int mode = 0; // Default mode

    lou_backTranslateString(tableList, inbuf, &inlen, outbuf, &outlen, typeform, spacing, mode);
}

static void fuzz_lou_translateString(const uint8_t *Data, size_t Size) {
    if (Size < 4) return; // Ensure there's enough data for basic use

    const char *tableList = "unicode.dis"; // Using a default table
    widechar inbuf[Size];
    int inlen = Size / sizeof(widechar);
    std::memcpy(inbuf, Data, inlen * sizeof(widechar));

    widechar outbuf[Size];
    int outlen = Size / sizeof(widechar);
    formtype *typeform = nullptr; // No typeform checking
    char *spacing = nullptr; // No spacing info
    int mode = 0; // Default mode

    lou_translateString(tableList, inbuf, &inlen, outbuf, &outlen, typeform, spacing, mode);
}

static void fuzz_lou_checkTable(const uint8_t *Data, size_t Size) {
    char tableList[Size + 1];
    std::memcpy(tableList, Data, Size);
    tableList[Size] = '\0'; // Null-terminate

    lou_checkTable(tableList);
}

static void fuzz_lou_indexTables(const uint8_t *Data, size_t Size) {
    if (Size < 2) return; // Ensure there's enough data for at least one table name

    std::vector<char> dataCopy(Data, Data + Size);
    dataCopy.push_back('\0'); // Ensure null-termination

    std::vector<char*> tables;
    char *current = dataCopy.data();
    char *end = current + Size;

    while (current < end && *current != '\0') {
        tables.push_back(current);
        size_t len = std::strlen(current);
        current += len + 1;
    }
    tables.push_back(nullptr); // Null-terminate the list

    lou_indexTables((const char **)tables.data());
}

static void fuzz_lou_findTable(const uint8_t *Data, size_t Size) {
    char query[Size + 1];
    std::memcpy(query, Data, Size);
    query[Size] = '\0'; // Null-terminate

    char *result = lou_findTable(query);
    if (result) {
        free(result);
    }
}

static void fuzz_lou_getTableInfo(const uint8_t *Data, size_t Size) {
    if (Size < 2) return; // Ensure there's enough data for table and key

    char table[Size / 2 + 1];
    char key[Size / 2 + 1];
    std::memcpy(table, Data, Size / 2);
    table[Size / 2] = '\0'; // Null-terminate
    std::memcpy(key, Data + Size / 2, Size / 2);
    key[Size / 2] = '\0'; // Null-terminate

    char *info = lou_getTableInfo(table, key);
    if (info) {
        free(info);
    }
}

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    fuzz_lou_backTranslateString(Data, Size);
    fuzz_lou_translateString(Data, Size);
    fuzz_lou_checkTable(Data, Size);
    fuzz_lou_indexTables(Data, Size);
    fuzz_lou_findTable(Data, Size);
    fuzz_lou_getTableInfo(Data, Size);
    return 0;
}