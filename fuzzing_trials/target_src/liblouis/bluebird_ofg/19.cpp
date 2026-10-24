#include <sys/stat.h>
#include <string.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "../../liblouis/liblouis.h"  // Correct header file for the function

    // Define widechar if it is not already defined
    typedef uint16_t widechar;
}

extern "C" int LLVMFuzzerTestOneInput_19(const uint8_t *data, size_t size) {
    if (size < 30) {  // Increase the minimum size to ensure there's enough data
        return 0;
    }

    // Initialize parameters
    const char *tableList = reinterpret_cast<const char*>(data);
    size_t tableListLength = strnlen(tableList, size);
    
    if (tableListLength >= size - 10) {
        return 0; // Ensure that tableList does not consume all data
    }

    const widechar *inbuf = reinterpret_cast<const widechar*>(data + tableListLength + 1); // Start after tableList
    int inlen = (size - tableListLength - 1) / sizeof(widechar); // Calculate length of input buffer

    if (inlen <= 0) {
        return 0; // Ensure there's enough data for inbuf
    }

    widechar outbuf[10]; // Output buffer
    int outlen = 10; // Length of output buffer

    formtype typeform = 0; // Initialize formtype
    char spacing[10]; // Spacing buffer
    int spbuflen = 10; // Length of spacing buffer

    // Call the function-under-test
    lou_backTranslateString(tableList, inbuf, &inlen, outbuf, &outlen, &typeform, spacing, spbuflen);

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

    LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
