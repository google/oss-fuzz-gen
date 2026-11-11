#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_464(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the test
    if (size < sizeof(cmsUInt32Number) + 2) {
        return 0;
    }
    
    // Initialize variables
    cmsMLU *mlu = cmsMLUalloc(NULL, 1);
    cmsUInt32Number code = *(cmsUInt32Number *)data;
    char language[3] = {'e', 'n', '\0'}; // Default to 'en'
    char country[3] = {'U', 'S', '\0'}; // Default to 'US'
    
    // Adjust pointers for language and country
    const uint8_t *languagePtr = data + sizeof(cmsUInt32Number);
    const uint8_t *countryPtr = languagePtr + 2;
    
    // Ensure we don't read out of bounds
    if (size >= sizeof(cmsUInt32Number) + 4) {
        language[0] = (char)languagePtr[0];
        language[1] = (char)languagePtr[1];
        country[0] = (char)countryPtr[0];
        country[1] = (char)countryPtr[1];
    }
    
    // Call the function-under-test
    cmsBool result = cmsMLUtranslationsCodes(mlu, code, language, country);
    
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_464(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
