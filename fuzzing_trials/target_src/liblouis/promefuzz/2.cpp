// This fuzz driver is generated for library liblouis, aiming to fuzz the following functions:
// lou_setLogLevel at logging.c:143:1 in liblouis.h
// lou_indexTables at metadata.c:947:1 in liblouis.h
// lou_findTable at metadata.c:1068:1 in liblouis.h
// lou_findTables at metadata.c:1115:1 in liblouis.h
// lou_free at compileTranslationTable.c:5379:1 in liblouis.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
extern "C" {
#include <liblouis.h>
}

#include <cstdint>
#include <cstdlib>
#include <cstring>

static void fuzz_lou_setLogLevel(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(logLevels)) return;
    logLevels level = static_cast<logLevels>(Data[0]);
    lou_setLogLevel(level);
}

static void fuzz_lou_indexTables(const uint8_t *Data, size_t Size) {
    const char *dummyTables[] = {"table1", "table2", "table3", nullptr};
    lou_indexTables(dummyTables);
}

static void fuzz_lou_findTable(const uint8_t *Data, size_t Size) {
    char *query = static_cast<char *>(malloc(Size + 1));
    if (!query) return;
    memcpy(query, Data, Size);
    query[Size] = '\0';
    
    char *result = lou_findTable(query);
    free(result);
    free(query);
}

static void fuzz_lou_findTables(const uint8_t *Data, size_t Size) {
    char *query = static_cast<char *>(malloc(Size + 1));
    if (!query) return;
    memcpy(query, Data, Size);
    query[Size] = '\0';
    
    char **results = lou_findTables(query);
    if (results) {
        for (char **ptr = results; *ptr != nullptr; ++ptr) {
            free(*ptr);
        }
        free(results);
    }
    free(query);
}

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    fuzz_lou_setLogLevel(Data, Size);
    fuzz_lou_indexTables(Data, Size);
    fuzz_lou_findTable(Data, Size);
    fuzz_lou_findTable(Data, Size);
    fuzz_lou_findTables(Data, Size);
    lou_free();
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

        LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    