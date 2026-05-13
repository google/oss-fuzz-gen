#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_86(const uint8_t *data, size_t size) {
    cmsMLU *mlu = NULL;
    cmsMLU *mlu_dup = NULL;
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Create an MLU object with some default values
    mlu = cmsMLUalloc(context, 1);

    // Ensure the MLU is not NULL
    if (mlu != NULL) {
        // Set some dummy data for the MLU
        cmsMLUsetASCII(mlu, "en", "US", "Test String");

        // Call the function-under-test
        mlu_dup = cmsMLUdup(mlu);

        // Clean up
        cmsMLUfree(mlu);
        cmsMLUfree(mlu_dup);
    }

    cmsDeleteContext(context);

    return 0;
}