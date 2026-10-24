// This fuzz driver is generated for library liblouis, aiming to fuzz the following functions:
// lou_charSize at compileTranslationTable.c:5425:1 in liblouis.h
// lou_translatePrehyphenated at lou_translateString.c:1410:1 in liblouis.h
// lou_checkTable at compileTranslationTable.c:5238:1 in liblouis.h
// lou_readCharFromFile at compileTranslationTable.c:4352:1 in liblouis.h
// lou_hyphenate at lou_translateString.c:4066:1 in liblouis.h
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
#include <cstdint>
#include <cstring>
#include <iostream>
#include "liblouis.h"

static void fuzz_lou_charSize() {
    // Call lou_charSize and ignore the return value as it's a constant.
    lou_charSize();
}

static void fuzz_lou_translatePrehyphenated(const uint8_t *Data, size_t Size) {
    if (Size < 2) return; // Ensure there is enough data to work with.

    // Allocate memory for tableList and ensure null-termination
    char tableList[256];
    size_t tableListLen = std::min(Size, sizeof(tableList) - 1);
    memcpy(tableList, Data, tableListLen);
    tableList[tableListLen] = '\0'; // Ensure null-termination.

    widechar inbuf[256];
    int inlen = std::min(Size, sizeof(inbuf) / sizeof(inbuf[0]));
    for (int i = 0; i < inlen; ++i) {
        inbuf[i] = Data[i];
    }
    widechar outbuf[256];
    int outlen = sizeof(outbuf) / sizeof(outbuf[0]);
    formtype typeform[256] = {0};
    char spacing[256] = {0};
    int outputPos[256] = {0};
    int inputPos[256] = {0};
    int cursorPos = 0;
    char inputHyphens[256] = {0};
    char outputHyphens[256] = {0};
    int mode = 0;

    lou_translatePrehyphenated(tableList, inbuf, &inlen, outbuf, &outlen, typeform, spacing, outputPos, inputPos, &cursorPos, inputHyphens, outputHyphens, mode);
}

static void fuzz_lou_checkTable(const uint8_t *Data, size_t Size) {
    if (Size == 0) return;

    char tableList[256];
    size_t len = std::min(Size, sizeof(tableList) - 1);
    memcpy(tableList, Data, len);
    tableList[len] = '\0'; // Ensure null-termination.

    lou_checkTable(tableList);
}

static void fuzz_lou_readCharFromFile(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return;

    fwrite(Data, 1, Size, file);
    fclose(file);

    int mode = 1;
    lou_readCharFromFile("./dummy_file", &mode);
}

static void fuzz_lou_hyphenate(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    char tableList[256];
    size_t tableListLen = std::min(Size, sizeof(tableList) - 1);
    memcpy(tableList, Data, tableListLen);
    tableList[tableListLen] = '\0'; // Ensure null-termination.

    widechar inbuf[256];
    int inlen = std::min(Size, sizeof(inbuf) / sizeof(inbuf[0]));
    for (int i = 0; i < inlen; ++i) {
        inbuf[i] = Data[i];
    }
    char hyphens[256] = {0};
    int mode = 0;

    lou_hyphenate(tableList, inbuf, inlen, hyphens, mode);
}

static void fuzz_lou_compileString(const uint8_t *Data, size_t Size) {
    if (Size == 0) return;

    char tableList[128];
    size_t tableListLen = std::min(Size / 2, sizeof(tableList) - 1);
    memcpy(tableList, Data, tableListLen);
    tableList[tableListLen] = '\0';

    const char *inString = reinterpret_cast<const char*>(Data + tableListLen);
    lou_compileString(tableList, inString);
}

extern "C" int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size) {
    fuzz_lou_charSize();
    fuzz_lou_translatePrehyphenated(Data, Size);
    fuzz_lou_checkTable(Data, Size);
    fuzz_lou_readCharFromFile(Data, Size);
    fuzz_lou_hyphenate(Data, Size);
    fuzz_lou_compileString(Data, Size);

    return 0;
}