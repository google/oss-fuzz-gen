#include <stdint.h>
#include <stddef.h>
#include <wchar.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0; // Not enough data to proceed
    }

    // Initialize variables
    cmsMLU *mlu = cmsMLUalloc(NULL, 1);
    if (mlu == NULL) {
        return 0;
    }

    // Extract language and country codes from the input data
    char language[3] = { data[0], data[1], '\0' };
    char country[3] = { data[2], data[3], '\0' };

    // Use the remaining data as a string to set in the MLU
    size_t textSize = size - 4;
    char *text = (char *)malloc(textSize + 1);
    if (text == NULL) {
        cmsMLUfree(mlu);
        return 0;
    }
    memcpy(text, data + 4, textSize);
    text[textSize] = '\0';

    // Set a string in the MLU
    cmsMLUsetASCII(mlu, language, country, text);

    // Allocate memory for the wchar_t buffer
    cmsUInt32Number bufferSize = 256;  // Example buffer size
    wchar_t *buffer = (wchar_t *)malloc(bufferSize * sizeof(wchar_t));
    if (buffer == NULL) {
        free(text);
        cmsMLUfree(mlu);
        return 0;
    }

    // Call the function-under-test
    cmsUInt32Number result = cmsMLUgetWide(mlu, language, country, buffer, bufferSize);

    // Clean up
    free(buffer);
    free(text);
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

    LLVMFuzzerTestOneInput_30(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
