#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_158(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for the required parameters
    if (size < 4) return 0; // Ensure there's at least one byte for the string

    // Initialize the cmsMLU object
    cmsMLU *mlu = cmsMLUalloc(NULL, 1);

    // Create non-NULL strings for language and country
    const char *language = "en";
    const char *country = "US";

    // Allocate memory for the output buffer
    cmsUInt32Number bufferSize = 256;
    char *outputBuffer = (char *)malloc(bufferSize);

    if (outputBuffer == NULL) {
        cmsMLUfree(mlu);
        return 0;
    }

    // Ensure the data is null-terminated to prevent overflow in cmsMLUsetASCII
    char *nullTerminatedData = (char *)malloc(size + 1);
    if (nullTerminatedData == NULL) {
        free(outputBuffer);
        cmsMLUfree(mlu);
        return 0;
    }
    memcpy(nullTerminatedData, data, size);
    nullTerminatedData[size] = '\0';

    // Use the input data to set some values in the cmsMLU object
    cmsMLUsetASCII(mlu, language, country, nullTerminatedData);

    // Call the function-under-test
    cmsUInt32Number result = cmsMLUgetASCII(mlu, language, country, outputBuffer, bufferSize);

    // Clean up
    free(outputBuffer);
    free(nullTerminatedData);
    cmsMLUfree(mlu);

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

    LLVMFuzzerTestOneInput_158(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
