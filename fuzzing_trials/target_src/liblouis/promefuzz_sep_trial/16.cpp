// This fuzz driver is generated for library liblouis, aiming to fuzz the following functions:
// lou_translate at lou_translateString.c:1135:1 in liblouis.h
// lou_translateString at lou_translateString.c:1128:1 in liblouis.h
// lou_dotsToChar at lou_translateString.c:4150:1 in liblouis.h
// lou_backTranslate at lou_backTranslateString.c:159:1 in liblouis.h
// lou_backTranslateString at lou_backTranslateString.c:152:1 in liblouis.h
// lou_checkTable at compileTranslationTable.c:5238:1 in liblouis.h
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

static void fuzz_lou_dotsToChar(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    const char *tableList = reinterpret_cast<const char*>(Data);
    size_t tableListLen = strnlen(tableList, Size);
    if (tableListLen == Size) return;

    widechar inbuf[256];
    widechar outbuf[256];
    int length = (Size - tableListLen - 1) / sizeof(widechar);
    if (length > 256) length = 256;
    std::memcpy(inbuf, Data + tableListLen + 1, length * sizeof(widechar));

    int mode = 0;
    lou_dotsToChar(tableList, inbuf, outbuf, length, mode);
}

static void fuzz_lou_backTranslate(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    const char *tableList = reinterpret_cast<const char*>(Data);
    size_t tableListLen = strnlen(tableList, Size);
    if (tableListLen == Size) return;

    widechar inbuf[256];
    widechar outbuf[256];
    int inlen = (Size - tableListLen - 1) / sizeof(widechar);
    if (inlen > 256) inlen = 256;
    std::memcpy(inbuf, Data + tableListLen + 1, inlen * sizeof(widechar));

    int outlen = 256;
    int outputPos[256];
    int inputPos[256];
    int cursorPos = 0;
    int mode = 0;

    lou_backTranslate(tableList, inbuf, &inlen, outbuf, &outlen, nullptr, nullptr, outputPos, inputPos, &cursorPos, mode);
}

static void fuzz_lou_backTranslateString(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    const char *tableList = reinterpret_cast<const char*>(Data);
    size_t tableListLen = strnlen(tableList, Size);
    if (tableListLen == Size) return;

    widechar inbuf[256];
    widechar outbuf[256];
    int inlen = (Size - tableListLen - 1) / sizeof(widechar);
    if (inlen > 256) inlen = 256;
    std::memcpy(inbuf, Data + tableListLen + 1, inlen * sizeof(widechar));

    int outlen = 256;
    int mode = 0;

    lou_backTranslateString(tableList, inbuf, &inlen, outbuf, &outlen, nullptr, nullptr, mode);
}

static void fuzz_lou_checkTable(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    const char *tableList = reinterpret_cast<const char*>(Data);
    if (strnlen(tableList, Size) < Size) {
        lou_checkTable(tableList);
    }
}

static void fuzz_lou_translate(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    const char *tableList = reinterpret_cast<const char*>(Data);
    size_t tableListLen = strnlen(tableList, Size);
    if (tableListLen == Size) return;

    widechar inbuf[256];
    widechar outbuf[256];
    int inlen = (Size - tableListLen - 1) / sizeof(widechar);
    if (inlen > 256) inlen = 256;
    std::memcpy(inbuf, Data + tableListLen + 1, inlen * sizeof(widechar));

    int outlen = 256;
    int outputPos[256];
    int inputPos[256];
    int cursorPos = 0;
    int mode = 0;

    lou_translate(tableList, inbuf, &inlen, outbuf, &outlen, nullptr, nullptr, outputPos, inputPos, &cursorPos, mode);
}

static void fuzz_lou_translateString(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    const char *tableList = reinterpret_cast<const char*>(Data);
    size_t tableListLen = strnlen(tableList, Size);
    if (tableListLen == Size) return;

    widechar inbuf[256];
    widechar outbuf[256];
    int inlen = (Size - tableListLen - 1) / sizeof(widechar);
    if (inlen > 256) inlen = 256;
    std::memcpy(inbuf, Data + tableListLen + 1, inlen * sizeof(widechar));

    int outlen = 256;
    int mode = 0;

    lou_translateString(tableList, inbuf, &inlen, outbuf, &outlen, nullptr, nullptr, mode);
}

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    fuzz_lou_dotsToChar(Data, Size);
    fuzz_lou_backTranslate(Data, Size);
    fuzz_lou_backTranslateString(Data, Size);
    fuzz_lou_checkTable(Data, Size);
    fuzz_lou_translate(Data, Size);
    fuzz_lou_translateString(Data, Size);
    return 0;
}