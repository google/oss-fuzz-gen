#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" {
    #include "/src/liblouis/liblouis/liblouis.h"  // Correct path for the header containing lou_dotsToChar
}

extern "C" int LLVMFuzzerTestOneInput_37(const uint8_t *data, size_t size) {
    // Ensure that the input size is large enough to split into meaningful parts
    if (size < 4) {
        return 0;
    }

    // Split data into parts for the function parameters
    const char *dots = reinterpret_cast<const char *>(data);
    size_t dotsLength = size / 2;  // Use half of the data for dots

    // Allocate widechar arrays for the output parameters
    widechar output1[256];
    widechar output2[256];

    // Initialize the widechar arrays with some default values
    memset(output1, 0, sizeof(output1));
    memset(output2, 0, sizeof(output2));

    // Use some of the remaining data for the integers
    int intParam1 = static_cast<int>(data[dotsLength] % 256);  // Ensure it is within a reasonable range
    int intParam2 = static_cast<int>(data[dotsLength + 1] % 256);

    // Call the function-under-test
    lou_dotsToChar(dots, output1, output2, intParam1, intParam2);

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

    LLVMFuzzerTestOneInput_37(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
