// This fuzz driver is generated for library liblouis, aiming to fuzz the following functions:
// lou_getTypeformForEmphClass at compileTranslationTable.c:5244:1 in liblouis.h
// lou_getEmphClasses at compileTranslationTable.c:5070:1 in liblouis.h
// lou_freeEmphClasses at compileTranslationTable.c:5095:1 in liblouis.h
// lou_free at compileTranslationTable.c:5363:1 in liblouis.h
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
#include <cstdio>

static void fuzz_lou_getTypeformForEmphClass(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    char *tableList = (char *)malloc(Size / 2 + 1);
    char *emphClass = (char *)malloc(Size / 2 + 1);
    if (!tableList || !emphClass) {
        free(tableList);
        free(emphClass);
        return;
    }

    memcpy(tableList, Data, Size / 2);
    tableList[Size / 2] = '\0';
    memcpy(emphClass, Data + Size / 2, Size / 2);
    emphClass[Size / 2] = '\0';

    formtype result = lou_getTypeformForEmphClass(tableList, emphClass);

    free(tableList);
    free(emphClass);
}

static void fuzz_lou_getEmphClasses(const uint8_t *Data, size_t Size) {
    char *tableList = (char *)malloc(Size + 1);
    if (!tableList) return;

    memcpy(tableList, Data, Size);
    tableList[Size] = '\0';

    char const **emphClasses = lou_getEmphClasses(tableList);
    if (emphClasses) {
        lou_freeEmphClasses(emphClasses);
    }

    free(tableList);
}

extern "C" int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size) {
    // Fuzzing lou_getTypeformForEmphClass
    fuzz_lou_getTypeformForEmphClass(Data, Size);

    // Fuzzing lou_getEmphClasses
    fuzz_lou_getEmphClasses(Data, Size);

    // Cleanup
    lou_free();

    return 0;
}