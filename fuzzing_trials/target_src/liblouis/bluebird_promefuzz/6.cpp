#include <sys/stat.h>
#include <string.h>
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
#include "../../liblouis/liblouis.h"

extern "C" int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Create a null-terminated string from the input data
    char *inputStr = static_cast<char*>(malloc(Size + 1));
    if (!inputStr) return 0;
    memcpy(inputStr, Data, Size);
    inputStr[Size] = '\0';

    // Ensure inputStr is a valid string for tableList and inString
    if (strlen(inputStr) == 0) {
        free(inputStr);
        return 0;
    }

    // Fuzz lou_setDataPath
    lou_setDataPath(inputStr);

    // Fuzz lou_compileString
    lou_compileString(inputStr, inputStr);

    // Fuzz lou_getDataPath
    char *dataPath = lou_getDataPath();
    if (dataPath) {
        // Do something with dataPath if needed
    }

    // Fuzz lou_getTable
    const void *table = lou_getTable(inputStr);
    if (table) {
        // Do something with table if needed
    }

    // Fuzz lou_getEmphClasses
    char const **emphClasses = lou_getEmphClasses(inputStr);
    if (emphClasses) {
        // Free the returned array
        for (size_t i = 0; emphClasses[i] != nullptr; ++i) {
            free(const_cast<char*>(emphClasses[i]));
        }
        free(emphClasses);
    }

    // Fuzz lou_getTypeformForEmphClass
    lou_getTypeformForEmphClass(inputStr, inputStr);

    free(inputStr);
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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
