#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h> // Assuming the function is part of the Little CMS library

int LLVMFuzzerTestOneInput_135(const uint8_t *data, size_t size) {
    // Initialize the parameters for cmsIT8DefineDblFormat
    cmsHANDLE handle;
    char *formatString;

    // Ensure the size is sufficient for a null-terminated string
    if (size < 1) {
        return 0;
    }

    // Create a null-terminated string from the input data
    formatString = (char *)malloc(size + 1);
    if (formatString == NULL) {
        return 0;
    }
    memcpy(formatString, data, size);
    formatString[size] = '\0';

    // Create a dummy cmsHANDLE for testing purposes
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        free(formatString);
        return 0;
    }

    // Call the function-under-test and check its return value
    cmsIT8DefineDblFormat(handle, formatString);

    // Clean up
    cmsIT8Free(handle);
    free(formatString);

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

    LLVMFuzzerTestOneInput_135(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
