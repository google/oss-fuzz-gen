#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_291(const uint8_t *data, size_t size) {
    // Ensure size is large enough for the test
    if (size < 10) return 0;

    // Initialize cmsMLU object
    cmsMLU *mlu = cmsMLUalloc(NULL, 1);

    // Create language and country strings
    char language[3] = "en";
    char country[3] = "US";

    // Create buffer for translation output
    char output[256];
    char fallback[256];

    // Ensure the data is null-terminated for safe string operations
    char *text = (char *)malloc(size + 1);
    memcpy(text, data, size);
    text[size] = '\0';

    // Set some translation in the cmsMLU object
    cmsMLUsetASCII(mlu, language, country, text);

    // Call the function under test
    cmsMLUgetTranslation(mlu, language, country, output, fallback);

    // Clean up
    cmsMLUfree(mlu);
    free(text);

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

    LLVMFuzzerTestOneInput_291(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
