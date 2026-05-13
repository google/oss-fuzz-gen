#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_239(const uint8_t *data, size_t size) {
    if (size < 3) {
        return 0;
    }

    // Initialize the cmsMLU object
    cmsMLU *mlu = cmsMLUalloc(NULL, 1);
    if (mlu == NULL) {
        return 0;
    }

    // Prepare language and country codes
    const char *languageCode = "en";
    const char *countryCode = "US";

    // Allocate a buffer for the output string
    cmsUInt32Number bufferSize = 256;
    char *outputBuffer = (char *)malloc(bufferSize);
    if (outputBuffer == NULL) {
        cmsMLUfree(mlu);
        return 0;
    }

    // Call the function-under-test
    cmsUInt32Number result = cmsMLUgetASCII(mlu, languageCode, countryCode, outputBuffer, bufferSize);

    // Free resources
    free(outputBuffer);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_239(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
