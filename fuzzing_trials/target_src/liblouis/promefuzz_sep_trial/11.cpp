// This fuzz driver is generated for library liblouis, aiming to fuzz the following functions:
// lou_translate at lou_translateString.c:1135:1 in liblouis.h
// lou_translateString at lou_translateString.c:1128:1 in liblouis.h
// lou_dotsToChar at lou_translateString.c:4150:1 in liblouis.h
// lou_backTranslate at lou_backTranslateString.c:159:1 in liblouis.h
// lou_backTranslateString at lou_backTranslateString.c:152:1 in liblouis.h
// lou_checkTable at compileTranslationTable.c:5238:1 in liblouis.h
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

static void fuzz_lou_dotsToChar(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(char *) + sizeof(widechar) * 2 + sizeof(int)) return;

    const char *tableList = reinterpret_cast<const char *>(Data);
    size_t tableListSize = strnlen(tableList, Size);
    if (tableListSize + 1 + sizeof(widechar) * 2 + sizeof(int) > Size) return;

    widechar *inbuf = reinterpret_cast<widechar *>(const_cast<uint8_t *>(Data + tableListSize + 1));
    int length = (Size - tableListSize - 1) / sizeof(widechar);
    widechar *outbuf = new widechar[length];
    int mode = *reinterpret_cast<const int *>(Data + tableListSize + 1 + sizeof(widechar) * 2);

    lou_dotsToChar(tableList, inbuf, outbuf, length, mode);

    delete[] outbuf;
}

static void fuzz_lou_backTranslate(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(char *) + sizeof(widechar) * 2 + sizeof(int) * 5) return;

    const char *tableList = reinterpret_cast<const char *>(Data);
    size_t tableListSize = strnlen(tableList, Size);
    if (tableListSize + 1 + sizeof(widechar) * 2 + sizeof(int) * 5 > Size) return;

    widechar *inbuf = reinterpret_cast<widechar *>(const_cast<uint8_t *>(Data + tableListSize + 1));
    int inlen = (Size - tableListSize - 1) / sizeof(widechar);
    widechar *outbuf = new widechar[inlen];
    int outlen = inlen;
    formtype *typeform = nullptr;
    char *spacing = nullptr;
    int *outputPos = new int[inlen];
    int *inputPos = new int[outlen];
    int cursorPos = 0;
    int mode = *reinterpret_cast<const int *>(Data + tableListSize + 1 + sizeof(widechar) * 2);

    lou_backTranslate(tableList, inbuf, &inlen, outbuf, &outlen, typeform, spacing, outputPos, inputPos, &cursorPos, mode);

    delete[] outbuf;
    delete[] outputPos;
    delete[] inputPos;
}

static void fuzz_lou_backTranslateString(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(char *) + sizeof(widechar) * 2 + sizeof(int) * 4) return;

    const char *tableList = reinterpret_cast<const char *>(Data);
    size_t tableListSize = strnlen(tableList, Size);
    if (tableListSize + 1 + sizeof(widechar) * 2 + sizeof(int) * 4 > Size) return;

    widechar *inbuf = reinterpret_cast<widechar *>(const_cast<uint8_t *>(Data + tableListSize + 1));
    int inlen = (Size - tableListSize - 1) / sizeof(widechar);
    widechar *outbuf = new widechar[inlen];
    int outlen = inlen;
    formtype *typeform = nullptr;
    char *spacing = nullptr;
    int mode = *reinterpret_cast<const int *>(Data + tableListSize + 1 + sizeof(widechar) * 2);

    lou_backTranslateString(tableList, inbuf, &inlen, outbuf, &outlen, typeform, spacing, mode);

    delete[] outbuf;
}

static void fuzz_lou_checkTable(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    std::string tableList(reinterpret_cast<const char *>(Data), strnlen(reinterpret_cast<const char *>(Data), Size));
    lou_checkTable(tableList.c_str());
}

static void fuzz_lou_translate(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(char *) + sizeof(widechar) * 2 + sizeof(int) * 5) return;

    const char *tableList = reinterpret_cast<const char *>(Data);
    size_t tableListSize = strnlen(tableList, Size);
    if (tableListSize + 1 + sizeof(widechar) * 2 + sizeof(int) * 5 > Size) return;

    widechar *inbuf = reinterpret_cast<widechar *>(const_cast<uint8_t *>(Data + tableListSize + 1));
    int inlen = (Size - tableListSize - 1) / sizeof(widechar);
    widechar *outbuf = new widechar[inlen];
    int outlen = inlen;
    formtype *typeform = nullptr;
    char *spacing = nullptr;
    int *outputPos = new int[inlen];
    int *inputPos = new int[outlen];
    int cursorPos = 0;
    int mode = *reinterpret_cast<const int *>(Data + tableListSize + 1 + sizeof(widechar) * 2);

    lou_translate(tableList, inbuf, &inlen, outbuf, &outlen, typeform, spacing, outputPos, inputPos, &cursorPos, mode);

    delete[] outbuf;
    delete[] outputPos;
    delete[] inputPos;
}

static void fuzz_lou_translateString(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(char *) + sizeof(widechar) * 2 + sizeof(int) * 4) return;

    const char *tableList = reinterpret_cast<const char *>(Data);
    size_t tableListSize = strnlen(tableList, Size);
    if (tableListSize + 1 + sizeof(widechar) * 2 + sizeof(int) * 4 > Size) return;

    widechar *inbuf = reinterpret_cast<widechar *>(const_cast<uint8_t *>(Data + tableListSize + 1));
    int inlen = (Size - tableListSize - 1) / sizeof(widechar);
    widechar *outbuf = new widechar[inlen];
    int outlen = inlen;
    formtype *typeform = nullptr;
    char *spacing = nullptr;
    int mode = *reinterpret_cast<const int *>(Data + tableListSize + 1 + sizeof(widechar) * 2);

    lou_translateString(tableList, inbuf, &inlen, outbuf, &outlen, typeform, spacing, mode);

    delete[] outbuf;
}

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    fuzz_lou_dotsToChar(Data, Size);
    fuzz_lou_backTranslate(Data, Size);
    fuzz_lou_backTranslateString(Data, Size);
    fuzz_lou_checkTable(Data, Size);
    fuzz_lou_translate(Data, Size);
    fuzz_lou_translateString(Data, Size);
    return 0;
}