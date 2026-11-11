// This fuzz driver is generated for library liblouis, aiming to fuzz the following functions:
// lou_translateString at lou_translateString.c:1128:1 in liblouis.h
// lou_hyphenate at lou_translateString.c:4066:1 in liblouis.h
// lou_getTable at compileTranslationTable.c:5118:1 in liblouis.h
// lou_translatePrehyphenated at lou_translateString.c:1410:1 in liblouis.h
// lou_checkTable at compileTranslationTable.c:5238:1 in liblouis.h
// lou_translate at lou_translateString.c:1135:1 in liblouis.h
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

static void fuzz_lou_translatePrehyphenated(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    // Ensure null-terminated string for tableList
    char *tableList = new char[Size + 1];
    memcpy(tableList, Data, Size);
    tableList[Size] = '\0';

    widechar *inbuf = new widechar[Size];
    int inlen = Size;
    widechar *outbuf = new widechar[Size];
    int outlen = Size;
    formtype *typeform = new formtype[Size];
    char *spacing = new char[Size];
    int *outputPos = new int[Size];
    int *inputPos = new int[Size];
    int cursorPos = 0;
    char *inputHyphens = new char[Size];
    char *outputHyphens = new char[Size];
    int mode = 0;

    lou_translatePrehyphenated(tableList, inbuf, &inlen, outbuf, &outlen, typeform, spacing, outputPos, inputPos, &cursorPos, inputHyphens, outputHyphens, mode);

    delete[] tableList;
    delete[] inbuf;
    delete[] outbuf;
    delete[] typeform;
    delete[] spacing;
    delete[] outputPos;
    delete[] inputPos;
    delete[] inputHyphens;
    delete[] outputHyphens;
}

static void fuzz_lou_checkTable(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    // Ensure null-terminated string for tableList
    char *tableList = new char[Size + 1];
    memcpy(tableList, Data, Size);
    tableList[Size] = '\0';

    lou_checkTable(tableList);

    delete[] tableList;
}

static void fuzz_lou_translate(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    // Ensure null-terminated string for tableList
    char *tableList = new char[Size + 1];
    memcpy(tableList, Data, Size);
    tableList[Size] = '\0';

    widechar *inbuf = new widechar[Size];
    int inlen = Size;
    widechar *outbuf = new widechar[Size];
    int outlen = Size;
    formtype *typeform = new formtype[Size];
    char *spacing = new char[Size];
    int *outputPos = new int[Size];
    int *inputPos = new int[Size];
    int cursorPos = 0;
    int mode = 0;

    lou_translate(tableList, inbuf, &inlen, outbuf, &outlen, typeform, spacing, outputPos, inputPos, &cursorPos, mode);

    delete[] tableList;
    delete[] inbuf;
    delete[] outbuf;
    delete[] typeform;
    delete[] spacing;
    delete[] outputPos;
    delete[] inputPos;
}

static void fuzz_lou_translateString(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    // Ensure null-terminated string for tableList
    char *tableList = new char[Size + 1];
    memcpy(tableList, Data, Size);
    tableList[Size] = '\0';

    widechar *inbuf = new widechar[Size];
    int inlen = Size;
    widechar *outbuf = new widechar[Size];
    int outlen = Size;
    formtype *typeform = new formtype[Size];
    char *spacing = new char[Size];
    int mode = 0;

    lou_translateString(tableList, inbuf, &inlen, outbuf, &outlen, typeform, spacing, mode);

    delete[] tableList;
    delete[] inbuf;
    delete[] outbuf;
    delete[] typeform;
    delete[] spacing;
}

static void fuzz_lou_hyphenate(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    // Ensure null-terminated string for tableList
    char *tableList = new char[Size + 1];
    memcpy(tableList, Data, Size);
    tableList[Size] = '\0';

    widechar *inbuf = new widechar[Size];
    int inlen = Size;
    char *hyphens = new char[Size];
    int mode = 0;

    lou_hyphenate(tableList, inbuf, inlen, hyphens, mode);

    delete[] tableList;
    delete[] inbuf;
    delete[] hyphens;
}

static void fuzz_lou_getTable(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    // Ensure null-terminated string for tableList
    char *tableList = new char[Size + 1];
    memcpy(tableList, Data, Size);
    tableList[Size] = '\0';

    lou_getTable(tableList);

    delete[] tableList;
}

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    fuzz_lou_translatePrehyphenated(Data, Size);
    fuzz_lou_checkTable(Data, Size);
    fuzz_lou_translate(Data, Size);
    fuzz_lou_translateString(Data, Size);
    fuzz_lou_hyphenate(Data, Size);
    fuzz_lou_getTable(Data, Size);
    return 0;
}