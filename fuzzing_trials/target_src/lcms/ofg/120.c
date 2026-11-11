#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "lcms2_plugin.h" // Assuming this header contains the cmsIT8GetData function and cmsHANDLE type

int LLVMFuzzerTestOneInput_120(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to split into two non-empty strings
    if (size < 2) {
        return 0;
    }

    // Initialize a cmsHANDLE, assuming a function to create a handle exists
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Split the input data into two strings
    size_t half_size = size / 2;
    char *str1 = (char *)malloc(half_size + 1);
    char *str2 = (char *)malloc(size - half_size + 1);

    if (str1 == NULL || str2 == NULL) {
        free(str1);
        free(str2);
        cmsIT8Free(handle);
        return 0;
    }

    memcpy(str1, data, half_size);
    str1[half_size] = '\0';

    memcpy(str2, data + half_size, size - half_size);
    str2[size - half_size] = '\0';

    // Call the function-under-test
    const char *result = cmsIT8GetData(handle, str1, str2);

    // Clean up
    free(str1);
    free(str2);
    cmsIT8Free(handle);

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

    LLVMFuzzerTestOneInput_120(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
