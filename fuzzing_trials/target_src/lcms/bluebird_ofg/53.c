#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_53(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs
    if (size < 10) return 0;

    // Initialize a cmsMLU object
    cmsMLU *mlu = cmsMLUalloc(NULL, 1);

    // Create some dummy language and country codes
    const char *languageCode = "en";
    const char *countryCode = "US";

    // Allocate buffers for the output strings
    char output1[256];
    char output2[256];

    // Copy some data from the input to use as a translation
    size_t translationLength = size < 255 ? size : 255;
    char translation[256];
    memcpy(translation, data, translationLength);
    translation[translationLength] = '\0';

    // Set the translation in the cmsMLU object
    cmsMLUsetASCII(mlu, languageCode, countryCode, translation);

    // Call the function-under-test
    cmsBool result = cmsMLUgetTranslation(mlu, languageCode, countryCode, output1, output2);

    // Clean up
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

    LLVMFuzzerTestOneInput_53(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
