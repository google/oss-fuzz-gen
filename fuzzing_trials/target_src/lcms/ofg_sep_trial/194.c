#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_194(const uint8_t *data, size_t size) {
    cmsHANDLE dictHandle = NULL;

    // Create a dummy dictionary entry to ensure dictHandle is not NULL
    cmsMLU *mlu = cmsMLUalloc(NULL, 1);
    if (mlu != NULL) {
        cmsMLUsetASCII(mlu, "en", "US", "Test Entry");
        dictHandle = (cmsHANDLE)mlu;
    }

    // Call the function-under-test
    cmsDictFree(dictHandle);

    return 0;
}