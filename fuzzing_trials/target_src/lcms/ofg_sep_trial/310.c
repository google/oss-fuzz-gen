#include <stdint.h>
#include <stdlib.h>
#include <wchar.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_310(const uint8_t *data, size_t size) {
    // Initialize a cmsHANDLE variable
    cmsHANDLE dictHandle;
    
    // Create a dictionary with a non-NULL handle
    dictHandle = cmsDictAlloc(NULL);
    if (dictHandle == NULL) {
        return 0; // Exit if the dictionary allocation fails
    }

    // Define keys and values
    const wchar_t *key1 = L"key1";
    const wchar_t *value1 = L"value1";
    const wchar_t *key2 = L"key2";
    const wchar_t *value2 = L"value2";

    // Add some entries to the dictionary to ensure it is not empty
    cmsDictAddEntry(dictHandle, key1, value1, NULL, NULL);
    cmsDictAddEntry(dictHandle, key2, value2, NULL, NULL);

    // Call the function-under-test
    const cmsDICTentry *entryList = cmsDictGetEntryList(dictHandle);

    // Clean up the dictionary
    cmsDictFree(dictHandle);

    return 0;
}