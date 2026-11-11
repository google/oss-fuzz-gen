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
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    // Step 1: Call lou_version to get the version of liblouis
    const char *version = lou_version();
    if (version) {
        std::cout << "Liblouis version: " << version << std::endl;
    }

    // Step 2: Prepare a tableList from the input data
    char *tableList = nullptr;
    if (Size > 0) {
        tableList = static_cast<char *>(malloc(Size + 1));
        if (!tableList) {
            return 0; // Exit if memory allocation fails
        }
        memcpy(tableList, Data, Size);
        tableList[Size] = '\0'; // Null-terminate the string
    }

    // Step 3: Call lou_getEmphClasses with the prepared tableList
    char const **emphClasses = lou_getEmphClasses(tableList);
    if (emphClasses) {
        // Print the emphasis classes for debugging
        for (int i = 0; emphClasses[i] != nullptr; ++i) {
            std::cout << "Emphasis class: " << emphClasses[i] << std::endl;
        }
        // Step 4: Free the emphasis classes memory
        lou_freeEmphClasses(emphClasses);
    }

    // Step 5: Free the tableList memory if it was allocated
    if (tableList) {
        free(tableList);
    }

    // Step 6: Additional cleanup functions for completeness
    // These are called with NULL as they are safe to call with NULL
    lou_freeTableInfo(nullptr);
    lou_freeTableFile(nullptr);
    lou_freeTableFiles(nullptr);

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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
