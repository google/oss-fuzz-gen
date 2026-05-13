#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

// Define a reasonable size for cmsStage initialization
#define CMS_STAGE_SIZE 256

int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    cmsStage *stage = NULL;

    // Ensure size is sufficient for a meaningful test
    if (size < CMS_STAGE_SIZE) {
        return 0;
    }

    // Allocate memory for the cmsStage with a defined size
    stage = (cmsStage *)malloc(CMS_STAGE_SIZE);
    if (stage == NULL) {
        return 0;
    }

    // Initialize the cmsStage with some data
    memcpy(stage, data, CMS_STAGE_SIZE);

    // Call the function-under-test
    cmsStageFree(stage);

    return 0;
}