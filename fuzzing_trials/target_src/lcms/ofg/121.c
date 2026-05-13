#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "lcms2_plugin.h" // Assuming this header contains the declaration for cmsIT8GetData and cmsHANDLE

int LLVMFuzzerTestOneInput_121(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract meaningful strings
    if (size < 3) {
        return 0;
    }

    // Initialize a cmsHANDLE (assuming a function exists to create it)
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Split the input data into two strings
    size_t firstStringSize = size / 3;
    size_t secondStringSize = size / 3;
    size_t thirdStringSize = size - firstStringSize - secondStringSize;

    char *firstString = (char *)malloc(firstStringSize + 1);
    char *secondString = (char *)malloc(secondStringSize + 1);
    char *thirdString = (char *)malloc(thirdStringSize + 1);

    if (firstString == NULL || secondString == NULL || thirdString == NULL) {
        free(firstString);
        free(secondString);
        free(thirdString);
        cmsIT8Free(handle);
        return 0;
    }

    memcpy(firstString, data, firstStringSize);
    firstString[firstStringSize] = '\0';

    memcpy(secondString, data + firstStringSize, secondStringSize);
    secondString[secondStringSize] = '\0';

    memcpy(thirdString, data + firstStringSize + secondStringSize, thirdStringSize);
    thirdString[thirdStringSize] = '\0';

    // Call the function under test
    const char *result = cmsIT8GetData(handle, firstString, secondString);

    // Use the result in some way to avoid compiler optimizations removing the call
    if (result != NULL) {
        printf("Result: %s\n", result);
    }

    // Clean up
    free(firstString);
    free(secondString);
    free(thirdString);
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

    LLVMFuzzerTestOneInput_121(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
