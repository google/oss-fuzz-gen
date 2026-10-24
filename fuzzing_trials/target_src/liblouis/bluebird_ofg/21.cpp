#include <sys/stat.h>
#include <string.h>
#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" {
    #include "../../liblouis/liblouis.h"  // Correct path for lou_dotsToChar declaration
}

extern "C" int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for the function parameters
    if (size < 2) {  // Adjusted to ensure at least a single character and null terminator for dots
        return 0;
    }

    // Initialize the parameters
    char dots[256];
    size_t copySize = size < 255 ? size : 255;  // Ensure we don't exceed buffer size
    memcpy(dots, data, copySize);
    dots[copySize] = '\0';  // Null-terminate to prevent overflow in string functions

    // Allocate memory for widechar arrays
    widechar output1[256];
    widechar output2[256];

    // Ensure the arrays are not null and have some initial values
    memset(output1, 0, sizeof(output1));
    memset(output2, 0, sizeof(output2));

    // Set values for the integer parameters
    int length = static_cast<int>(copySize);
    int mode = 0;  // You can vary this value as needed

    // Call the function-under-test
    lou_dotsToChar(dots, output1, output2, length, mode);

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

    LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
