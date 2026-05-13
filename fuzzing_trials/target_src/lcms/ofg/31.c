#include <stdint.h>
#include <stddef.h>
#include <wchar.h>
#include <string.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_31(const uint8_t *data, size_t size) {
    // Ensure the input size is large enough to extract meaningful data
    if (size < 10) return 0;

    // Initialize cmsMLU structure
    cmsMLU *mlu = cmsMLUalloc(NULL, 1);

    // Extract strings from the data
    const char *language = (const char *)data;
    const char *country = (const char *)(data + 1);

    // Allocate memory for the wchar_t output buffer
    cmsUInt32Number bufferSize = 256;
    wchar_t *outputBuffer = (wchar_t *)malloc(bufferSize * sizeof(wchar_t));
    if (outputBuffer == NULL) {
        cmsMLUfree(mlu);
        return 0;
    }

    // Call the function-under-test
    cmsUInt32Number result = cmsMLUgetWide(mlu, language, country, outputBuffer, bufferSize);

    // Clean up
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

    LLVMFuzzerTestOneInput_31(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
