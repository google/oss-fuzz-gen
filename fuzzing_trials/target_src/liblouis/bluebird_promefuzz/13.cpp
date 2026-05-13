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
#include "../../liblouis/liblouis.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>

static char** dummyResolver(const char* table, const char* base) {
    // Dummy resolver that returns a static list of paths
    static char* paths[] = { "./dummy_table_path", NULL };
    return paths;
}

extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare input data
    char* inputData = (char*)malloc(Size + 1);
    if (!inputData) return 0;
    memcpy(inputData, Data, Size);
    inputData[Size] = '\0';

    // Use the first byte to decide which function to target
    uint8_t choice = Data[0] % 6;

    switch (choice) {
        case 0: {
            // Test lou_compileString
            // Ensure inString is not empty to avoid dereferencing null
            if (Size > 1) {
                char* inString = inputData + 1;
                // Check if table is valid before calling lou_compileString
                if (lou_getTable(inputData)) {
                    lou_compileString(inputData, inString);
                }
            }
            break;
        }
        case 1: {
            // Test lou_checkTable
            lou_checkTable(inputData);
            break;
        }
        case 2: {
            // Test lou_getTable
            lou_getTable(inputData);
            break;
        }
        case 3: {
            // Test lou_getEmphClasses
            char const **emphClasses = lou_getEmphClasses(inputData);
            if (emphClasses) {
                for (size_t i = 0; emphClasses[i] != NULL; ++i) {
                    free((void*)emphClasses[i]);
                }
                free(emphClasses);
            }
            break;
        }
        case 4: {
            // Test lou_getTypeformForEmphClass
            // Ensure emphClass is not empty
            if (Size > 1) {
                lou_getTypeformForEmphClass(inputData, inputData + 1);
            }
            break;
        }
        case 5: {
            // Test lou_registerTableResolver
            lou_registerTableResolver(dummyResolver);
            break;
        }
    }

    free(inputData);
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

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
