#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include "../../liblouis/liblouis.h"
}

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    // Define and initialize variables
    const char *tableList = "en-us-g2.ctb"; // Example table list
    widechar inputText[256] = {0}; // Initialize input buffer to zero
    widechar outputBuffer[256] = {0}; // Initialize output buffer to zero
    int inputLength = 256;
    int outputLength = 256;

    // Ensure data is not NULL and size is greater than 0
    if (data == NULL || size == 0) {
        return 0;
    }

    // Copy data into inputText, ensuring no overflow
    size_t copySize = size < (sizeof(inputText) / sizeof(widechar)) ? size : (sizeof(inputText) / sizeof(widechar));
    memcpy(inputText, data, copySize);

    // Call the function-under-test
    lou_charToDots(tableList, inputText, outputBuffer, inputLength, outputLength);

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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
