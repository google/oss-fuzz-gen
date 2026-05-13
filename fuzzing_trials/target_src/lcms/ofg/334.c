#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_334(const uint8_t *data, size_t size) {
    // Ensure there is enough data to create non-null strings
    if (size < 4) {
        return 0;
    }

    // Initialize variables
    cmsMLU *mlu = cmsMLUalloc(NULL, 1);
    if (mlu == NULL) {
        return 0;
    }

    // Create non-null strings for language and country
    const char *language = (const char *)data;
    const char *country = (const char *)(data + 1);

    // Create a non-null wide character string
    wchar_t wideString[2];
    wideString[0] = (wchar_t)data[2];
    wideString[1] = L'\0';

    // Call the function-under-test
    cmsBool result = cmsMLUsetWide(mlu, language, country, wideString);

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

    LLVMFuzzerTestOneInput_334(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
