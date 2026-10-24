#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to extract necessary data
    if (size < sizeof(cmsUInt32Number) + 2) {
        return 0;
    }

    // Extract a cmsUInt32Number from the data
    cmsUInt32Number code = *((cmsUInt32Number *)data);
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);

    // Allocate memory for cmsMLU structure
    cmsMLU *mlu = cmsMLUalloc(NULL, 1);
    if (mlu == NULL) {
        return 0;
    }

    // Extract two non-NULL char pointers from the data
    char *langCode = (char *)malloc(2);
    char *countryCode = (char *)malloc(2);
    if (langCode == NULL || countryCode == NULL) {
        cmsMLUfree(mlu);
        free(langCode);
        free(countryCode);
        return 0;
    }

    // Copy data to langCode and countryCode
    memcpy(langCode, data, 2);
    memcpy(countryCode, data + 2, 2);

    // Null-terminate the strings
    langCode[1] = '\0';
    countryCode[1] = '\0';

    // Call the function-under-test
    cmsBool result = cmsMLUtranslationsCodes(mlu, code, langCode, countryCode);

    // Clean up
    cmsMLUfree(mlu);
    free(langCode);
    free(countryCode);

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

    LLVMFuzzerTestOneInput_101(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
