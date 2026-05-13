#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

// Fuzzing harness for cmsMLUfree
int LLVMFuzzerTestOneInput_198(const uint8_t *data, size_t size) {
    // Initialize a cmsMLU object
    cmsMLU *mlu = cmsMLUalloc(NULL, 1);

    // Ensure mlu is not NULL
    if (mlu == NULL) {
        return 0;
    }

    // Optionally, populate the cmsMLU object with some data
    // Here we use some arbitrary values for demonstration purposes
    cmsMLUsetASCII(mlu, "en", "US", "Sample Text");

    // Call the function-under-test
    cmsMLUfree(mlu);

    return 0;
}