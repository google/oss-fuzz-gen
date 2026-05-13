#include <stdint.h>
#include <wchar.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_275(const uint8_t *data, size_t size) {
    cmsHANDLE dictHandle;
    wchar_t key[256];
    wchar_t value[256];
    cmsMLU *displayName;
    cmsMLU *displayValue;
    cmsBool result;

    // Initialize the dictionary handle
    dictHandle = cmsDictAlloc(NULL);
    if (dictHandle == NULL) {
        return 0;
    }

    // Ensure that the data size is sufficient to fill key and value
    if (size < sizeof(key) + sizeof(value)) {
        cmsDictFree(dictHandle);
        return 0;
    }

    // Copy data to key and value, ensuring null termination
    wcsncpy(key, (const wchar_t *)data, sizeof(key) / sizeof(wchar_t) - 1);
    key[sizeof(key) / sizeof(wchar_t) - 1] = L'\0';
    wcsncpy(value, (const wchar_t *)(data + sizeof(key)), sizeof(value) / sizeof(wchar_t) - 1);
    value[sizeof(value) / sizeof(wchar_t) - 1] = L'\0';

    // Allocate displayName and displayValue
    displayName = cmsMLUalloc(NULL, 1);
    displayValue = cmsMLUalloc(NULL, 1);

    if (displayName != NULL && displayValue != NULL) {
        // Set some dummy data to displayName and displayValue
        cmsMLUsetWide(displayName, "en", "US", key);
        cmsMLUsetWide(displayValue, "en", "US", value);

        // Call the function under test
        result = cmsDictAddEntry(dictHandle, key, value, displayName, displayValue);
    }

    // Clean up
    if (displayName != NULL) cmsMLUfree(displayName);
    if (displayValue != NULL) cmsMLUfree(displayValue);
    cmsDictFree(dictHandle);

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

    LLVMFuzzerTestOneInput_275(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
