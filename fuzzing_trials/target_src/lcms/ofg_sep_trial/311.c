#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2_plugin.h>
#include <wchar.h> // Include for wchar_t

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_311(const uint8_t *data, size_t size) {
    cmsHANDLE dictHandle = NULL;
    const cmsDICTentry *entryList = NULL;

    // Initialize a dictionary handle using the data provided
    if (size > 0) {
        dictHandle = cmsDictAlloc(NULL);
        if (dictHandle != NULL) {
            // Add a dummy entry to ensure the dictionary is not empty
            // Use dummy wchar_t strings for Name and Value
            const wchar_t *dummyName = L"DummyName";
            const wchar_t *dummyValue = L"DummyValue";
            cmsDictAddEntry(dictHandle, dummyName, dummyValue, (const cmsMLU*)data, (const cmsMLU*)data);
        }
    }

    // Call the function-under-test
    entryList = cmsDictGetEntryList(dictHandle);

    // Cleanup
    if (dictHandle != NULL) {
        cmsDictFree(dictHandle);
    }

    return 0;
}

#ifdef __cplusplus
}
#endif