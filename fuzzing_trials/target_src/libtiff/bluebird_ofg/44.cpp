#include <sys/stat.h>
#include <string.h>
#include <cstddef>
#include "cstdint"
#include <cstdio>
#include "cstring"

extern "C" {
    #include "tiffio.h"  // Include the necessary header for TIFF functions
}

extern "C" int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to create non-null strings
    if (size < 2) return 0;

    // Create two strings from the input data
    char str1[256];
    char str2[256];

    size_t half_size = size / 2;
    size_t str1_len = (half_size < 255) ? half_size : 255;
    size_t str2_len = (size - half_size < 255) ? size - half_size : 255;

    // Copy data into strings and null-terminate them
    memcpy(str1, data, str1_len);
    str1[str1_len] = '\0';

    memcpy(str2, data + half_size, str2_len);
    str2[str2_len] = '\0';

    // Call the function-under-test
    // Use a valid format specifier for the warning message
    TIFFWarning(str1, "%s", str2);

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

    LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
