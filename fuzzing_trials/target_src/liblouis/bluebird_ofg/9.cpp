#include <sys/stat.h>
#include <string.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>

extern "C" {
    #include "../../liblouis/liblouis.h"  // Correct header file for lou_hyphenate
}

extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
    // Ensure there's enough data to work with
    if (size < 4) {
        return 0;
    }

    // Split the input data into parts for each parameter
    size_t charDataSize = size / 4;
    size_t wideCharDataSize = size / 4;
    size_t hyphenBufferSize = size / 2;
    int patternSize = static_cast<int>(size / 4);

    // Allocate and initialize memory for each parameter
    char *charData = new char[charDataSize + 1];
    widechar *wideCharData = new widechar[wideCharDataSize + 1];
    char *hyphenBuffer = new char[hyphenBufferSize + 1];

    // Copy data into allocated memory
    memcpy(charData, data, charDataSize);
    charData[charDataSize] = '\0';  // Null-terminate the string

    memcpy(wideCharData, data + charDataSize, wideCharDataSize * sizeof(widechar));
    wideCharData[wideCharDataSize] = 0;  // Null-terminate the widechar array

    memset(hyphenBuffer, 0, hyphenBufferSize + 1);  // Initialize hyphen buffer

    // Call the function-under-test
    lou_hyphenate(charData, wideCharData, patternSize, hyphenBuffer, hyphenBufferSize);

    // Clean up
    delete[] charData;
    delete[] wideCharData;
    delete[] hyphenBuffer;

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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
