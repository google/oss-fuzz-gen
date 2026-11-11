#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>
#include "/src/lcms/include/lcms2.h"

int LLVMFuzzerTestOneInput_366(const uint8_t *data, size_t size) {
    // Check if size is sufficient for processing
    if (size < sizeof(cmsFloat32Number)) {
        return 0;
    }

    // Initialize a cmsStage object
    cmsStage *stage = cmsStageAllocIdentity(NULL, 1);

    // Ensure the stage is not NULL
    if (stage == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsStageSignature result = cmsStageType(stage);

    // Clean up
    cmsStageFree(stage);

    return 0;
}