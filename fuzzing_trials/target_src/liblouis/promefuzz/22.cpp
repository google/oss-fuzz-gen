// This fuzz driver is generated for library liblouis, aiming to fuzz the following functions:
// lou_getEmphClasses at compileTranslationTable.c:5086:1 in liblouis.h
// lou_freeEmphClasses at compileTranslationTable.c:5111:1 in liblouis.h
// lou_getTableInfo at metadata.c:1147:1 in liblouis.h
// lou_freeTableInfo at metadata.c:1172:1 in liblouis.h
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

extern "C" int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Ensure null-termination for the input data
    char *tableList = static_cast<char *>(malloc(Size + 1));
    if (!tableList) {
        return 0;
    }
    memcpy(tableList, Data, Size);
    tableList[Size] = '\0';

    // Test lou_getEmphClasses
    char const **emphClasses = lou_getEmphClasses(tableList);
    if (emphClasses) {
        lou_freeEmphClasses(emphClasses);
    }

    // Test lou_getTableInfo with a dummy key
    char *key = "dummyKey";
    char *tableInfo = lou_getTableInfo(tableList, key);
    if (tableInfo) {
        lou_freeTableInfo(tableInfo);
    }

    // Do not free tableList with lou_freeTableFile since it was not allocated by liblouis
    // Free the allocated tableList
    free(tableList);

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

        LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    