#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "lcms2.h"  // Assuming the function is part of the Little CMS library

int LLVMFuzzerTestOneInput_488(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for splitting into strings
    if (size < 4) {
        return 0;
    }

    // Allocate memory for the strings, ensuring null termination
    size_t str_size = size / 4;
    char *str1 = (char *)malloc(str_size + 1);
    char *str2 = (char *)malloc(str_size + 1);
    char *str3 = (char *)malloc(str_size + 1);

    if (str1 == NULL || str2 == NULL || str3 == NULL) {
        free(str1);
        free(str2);
        free(str3);
        return 0;
    }

    // Copy data into strings and ensure null termination
    memcpy(str1, data, str_size);
    str1[str_size] = '\0';
    memcpy(str2, data + str_size, str_size);
    str2[str_size] = '\0';
    memcpy(str3, data + 2 * str_size, str_size);
    str3[str_size] = '\0';

    // Create a dummy cmsHANDLE for testing
    cmsHANDLE handle = cmsIT8Alloc(NULL);

    // Call the function-under-test
    cmsIT8SetTableByLabel(handle, str1, str2, str3);

    // Clean up
    cmsIT8Free(handle);
    free(str1);
    free(str2);
    free(str3);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_488(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
