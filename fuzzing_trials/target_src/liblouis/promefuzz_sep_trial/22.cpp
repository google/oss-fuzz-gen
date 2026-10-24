// This fuzz driver is generated for library liblouis, aiming to fuzz the following functions:
// lou_hyphenate at lou_translateString.c:4066:1 in liblouis.h
// lou_charToDots at lou_translateString.c:4173:1 in liblouis.h
// lou_getTableInfo at metadata.c:1142:1 in liblouis.h
// lou_translatePrehyphenated at lou_translateString.c:1410:1 in liblouis.h
// lou_translate at lou_translateString.c:1135:1 in liblouis.h
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
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <liblouis.h>

static void fuzz_lou_translatePrehyphenated(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    const char *tableList = "./dummy_table";
    widechar *inbuf = (widechar *)malloc(Size * sizeof(widechar));
    int inlen = Size;
    widechar *outbuf = (widechar *)malloc(Size * sizeof(widechar));
    int outlen = Size;
    formtype *typeform = (formtype *)malloc(Size * sizeof(formtype));
    char *spacing = (char *)malloc(Size);
    int *outputPos = (int *)malloc(Size * sizeof(int));
    int *inputPos = (int *)malloc(Size * sizeof(int));
    int cursorPos = 0;
    char *inputHyphens = (char *)malloc(Size);
    char *outputHyphens = (char *)malloc(Size);
    int mode = 0;

    memcpy(inbuf, Data, Size);
    memset(typeform, 0, Size * sizeof(formtype));
    memset(spacing, 0, Size);
    memset(inputHyphens, 0, Size);
    memset(outputHyphens, 0, Size);

    lou_translatePrehyphenated(tableList, inbuf, &inlen, outbuf, &outlen, typeform, spacing, outputPos, inputPos, &cursorPos, inputHyphens, outputHyphens, mode);

    free(inbuf);
    free(outbuf);
    free(typeform);
    free(spacing);
    free(outputPos);
    free(inputPos);
    free(inputHyphens);
    free(outputHyphens);
}

static void fuzz_lou_translate(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    const char *tableList = "./dummy_table";
    widechar *inbuf = (widechar *)malloc(Size * sizeof(widechar));
    int inlen = Size;
    widechar *outbuf = (widechar *)malloc(Size * sizeof(widechar));
    int outlen = Size;
    formtype *typeform = (formtype *)malloc(Size * sizeof(formtype));
    char *spacing = (char *)malloc(Size);
    int *outputPos = (int *)malloc(Size * sizeof(int));
    int *inputPos = (int *)malloc(Size * sizeof(int));
    int cursorPos = 0;
    int mode = 0;

    memcpy(inbuf, Data, Size);
    memset(typeform, 0, Size * sizeof(formtype));
    memset(spacing, 0, Size);

    lou_translate(tableList, inbuf, &inlen, outbuf, &outlen, typeform, spacing, outputPos, inputPos, &cursorPos, mode);

    free(inbuf);
    free(outbuf);
    free(typeform);
    free(spacing);
    free(outputPos);
    free(inputPos);
}

static void fuzz_lou_translateString(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    const char *tableList = "./dummy_table";
    widechar *inbuf = (widechar *)malloc(Size * sizeof(widechar));
    int inlen = Size;
    widechar *outbuf = (widechar *)malloc(Size * sizeof(widechar));
    int outlen = Size;
    formtype *typeform = (formtype *)malloc(Size * sizeof(formtype));
    char *spacing = (char *)malloc(Size);
    int mode = 0;

    memcpy(inbuf, Data, Size);
    memset(typeform, 0, Size * sizeof(formtype));
    memset(spacing, 0, Size);

    lou_translateString(tableList, inbuf, &inlen, outbuf, &outlen, typeform, spacing, mode);

    free(inbuf);
    free(outbuf);
    free(typeform);
    free(spacing);
}

static void fuzz_lou_hyphenate(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    const char *tableList = "./dummy_table";
    widechar *inbuf = (widechar *)malloc(Size * sizeof(widechar));
    int inlen = Size;
    char *hyphens = (char *)malloc(Size);
    int mode = 0;

    memcpy(inbuf, Data, Size);
    memset(hyphens, 0, Size);

    lou_hyphenate(tableList, inbuf, inlen, hyphens, mode);

    free(inbuf);
    free(hyphens);
}

static void fuzz_lou_charToDots(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    const char *tableList = "./dummy_table";
    widechar *inbuf = (widechar *)malloc(Size * sizeof(widechar));
    widechar *outbuf = (widechar *)malloc(Size * sizeof(widechar));
    int length = Size;
    int mode = 0;

    memcpy(inbuf, Data, Size);

    lou_charToDots(tableList, inbuf, outbuf, length, mode);

    free(inbuf);
    free(outbuf);
}

static void fuzz_lou_getTableInfo(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    const char *table = "./dummy_table";
    char *key = (char *)malloc(Size + 1);
    memcpy(key, Data, Size);
    key[Size] = '\0';

    char *result = lou_getTableInfo(table, key);
    if (result) {
        free(result);
    }

    free(key);
}

extern "C" int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    fuzz_lou_translatePrehyphenated(Data, Size);
    fuzz_lou_translate(Data, Size);
    fuzz_lou_translateString(Data, Size);
    fuzz_lou_hyphenate(Data, Size);
    fuzz_lou_charToDots(Data, Size);
    fuzz_lou_getTableInfo(Data, Size);

    return 0;
}