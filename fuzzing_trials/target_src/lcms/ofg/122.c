#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_122(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for the test
    if (size < 4) { // Adjusted to ensure we have enough data for both language and country
        return 0;
    }

    // Initialize the parameters for cmsMLUgetUTF8
    cmsMLU *mlu = cmsMLUalloc(NULL, 1);
    if (mlu == NULL) {
        return 0;
    }

    // Use parts of the input data for language and country codes
    char language[3] = { (char)data[0], (char)data[1], '\0' };
    char country[3] = { (char)data[2], (char)data[3], '\0' };

    // Allocate a buffer for the output
    cmsUInt32Number bufferSize = 256;
    char *outputBuffer = (char *)malloc(bufferSize);
    if (outputBuffer == NULL) {
        cmsMLUfree(mlu);
        return 0;
    }

    // Call the function-under-test
    cmsUInt32Number result = cmsMLUgetUTF8(mlu, language, country, outputBuffer, bufferSize);

    // Free allocated resources
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

    LLVMFuzzerTestOneInput_122(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
