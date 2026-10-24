#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_440(const uint8_t *data, size_t size) {
    // Initialize parameters for cmsGetSupportedIntents
    cmsUInt32Number intent = 0;
    cmsUInt32Number supportedIntents;
    char *description = (char *)malloc(256); // Allocate memory for description

    if (description == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Ensure the description is initialized
    snprintf(description, 256, "Default Description");

    // Call the function-under-test
    cmsUInt32Number result = cmsGetSupportedIntents(intent, &supportedIntents, &description);

    // Use the result in some way to prevent compiler optimizations from removing the call
    if (result != 0) {
        printf("Supported Intents: %u, Description: %s\n", supportedIntents, description);
    }

    // Free allocated memory
    free(description);

    return 0;
}