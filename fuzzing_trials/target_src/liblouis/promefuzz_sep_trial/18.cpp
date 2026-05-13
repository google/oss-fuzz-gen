// This fuzz driver is generated for library liblouis, aiming to fuzz the following functions:
// lou_translate at lou_translateString.c:1135:1 in liblouis.h
// lou_getTypeformForEmphClass at compileTranslationTable.c:5244:1 in liblouis.h
// lou_backTranslate at lou_backTranslateString.c:159:1 in liblouis.h
// lou_translatePrehyphenated at lou_translateString.c:1410:1 in liblouis.h
// lou_backTranslateString at lou_backTranslateString.c:152:1 in liblouis.h
// lou_translateString at lou_translateString.c:1128:1 in liblouis.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <fstream>
#include <liblouis.h>

static void fuzz_lou_backTranslate(const uint8_t *Data, size_t Size) {
    const char *tableList = "./dummy_file";
    std::ofstream file(tableList);
    file.write(reinterpret_cast<const char *>(Data), Size);
    file.close();

    widechar inbuf[256];
    widechar outbuf[256];
    int inlen = Size < 256 ? Size / sizeof(widechar) : 256;
    int outlen = 256;
    formtype typeform[256];
    char spacing[256];
    int outputPos[256];
    int inputPos[256];
    int cursorPos = 0;
    int mode = 0;

    std::memset(inbuf, 0, sizeof(inbuf));
    std::memcpy(inbuf, Data, inlen * sizeof(widechar));

    lou_backTranslate(tableList, inbuf, &inlen, outbuf, &outlen, typeform, spacing, outputPos, inputPos, &cursorPos, mode);
}

static void fuzz_lou_translatePrehyphenated(const uint8_t *Data, size_t Size) {
    const char *tableList = "./dummy_file";
    std::ofstream file(tableList);
    file.write(reinterpret_cast<const char *>(Data), Size);
    file.close();

    widechar inbuf[256];
    widechar outbuf[256];
    int inlen = Size < 256 ? Size / sizeof(widechar) : 256;
    int outlen = 256;
    formtype typeform[256];
    char spacing[256];
    int outputPos[256];
    int inputPos[256];
    int cursorPos = 0;
    char inputHyphens[256];
    char outputHyphens[256];
    int mode = 0;

    std::memset(inbuf, 0, sizeof(inbuf));
    std::memcpy(inbuf, Data, inlen * sizeof(widechar));

    lou_translatePrehyphenated(tableList, inbuf, &inlen, outbuf, &outlen, typeform, spacing, outputPos, inputPos, &cursorPos, inputHyphens, outputHyphens, mode);
}

static void fuzz_lou_backTranslateString(const uint8_t *Data, size_t Size) {
    const char *tableList = "./dummy_file";
    std::ofstream file(tableList);
    file.write(reinterpret_cast<const char *>(Data), Size);
    file.close();

    widechar inbuf[256];
    widechar outbuf[256];
    int inlen = Size < 256 ? Size / sizeof(widechar) : 256;
    int outlen = 256;
    formtype typeform[256];
    char spacing[256];
    int mode = 0;

    std::memset(inbuf, 0, sizeof(inbuf));
    std::memcpy(inbuf, Data, inlen * sizeof(widechar));

    lou_backTranslateString(tableList, inbuf, &inlen, outbuf, &outlen, typeform, spacing, mode);
}

static void fuzz_lou_translateString(const uint8_t *Data, size_t Size) {
    const char *tableList = "./dummy_file";
    std::ofstream file(tableList);
    file.write(reinterpret_cast<const char *>(Data), Size);
    file.close();

    widechar inbuf[256];
    widechar outbuf[256];
    int inlen = Size < 256 ? Size / sizeof(widechar) : 256;
    int outlen = 256;
    formtype typeform[256];
    char spacing[256];
    int mode = 0;

    std::memset(inbuf, 0, sizeof(inbuf));
    std::memcpy(inbuf, Data, inlen * sizeof(widechar));

    lou_translateString(tableList, inbuf, &inlen, outbuf, &outlen, typeform, spacing, mode);
}

static void fuzz_lou_translate(const uint8_t *Data, size_t Size) {
    const char *tableList = "./dummy_file";
    std::ofstream file(tableList);
    file.write(reinterpret_cast<const char *>(Data), Size);
    file.close();

    widechar inbuf[256];
    widechar outbuf[256];
    int inlen = Size < 256 ? Size / sizeof(widechar) : 256;
    int outlen = 256;
    formtype typeform[256];
    char spacing[256];
    int outputPos[256];
    int inputPos[256];
    int cursorPos = 0;
    int mode = 0;

    std::memset(inbuf, 0, sizeof(inbuf));
    std::memcpy(inbuf, Data, inlen * sizeof(widechar));

    lou_translate(tableList, inbuf, &inlen, outbuf, &outlen, typeform, spacing, outputPos, inputPos, &cursorPos, mode);
}

static void fuzz_lou_getTypeformForEmphClass(const uint8_t *Data, size_t Size) {
    const char *tableList = "./dummy_file";
    std::ofstream file(tableList);
    file.write(reinterpret_cast<const char *>(Data), Size);
    file.close();

    const char *emphClass = reinterpret_cast<const char *>(Data);

    lou_getTypeformForEmphClass(tableList, emphClass);
}

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    fuzz_lou_backTranslate(Data, Size);
    fuzz_lou_translatePrehyphenated(Data, Size);
    fuzz_lou_backTranslateString(Data, Size);
    fuzz_lou_translateString(Data, Size);
    fuzz_lou_translate(Data, Size);
    fuzz_lou_getTypeformForEmphClass(Data, Size);

    return 0;
}