#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_426(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsMLU *mlu = cmsMLUalloc(NULL, 1);
    const char *language = "en";
    const char *country = "US";
    char *asciiString = NULL;

    // Ensure size is non-zero and allocate memory for asciiString
    if (size > 0) {
        asciiString = (char *)malloc(size + 1);
        if (asciiString == NULL) {
            cmsMLUfree(mlu);
            return 0;
        }

        // Copy data to asciiString and null-terminate it
        memcpy(asciiString, data, size);
        asciiString[size] = '\0';

        // Call the function-under-test
        cmsMLUsetASCII(mlu, language, country, asciiString);

        // Free allocated memory
        free(asciiString);
    }

    // Free cmsMLU object
    cmsMLUfree(mlu);

    return 0;
}