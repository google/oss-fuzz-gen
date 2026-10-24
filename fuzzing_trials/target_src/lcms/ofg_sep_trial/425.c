#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_425(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsUInt32Number rows = 3; // Example value, adjust as needed
    cmsUInt32Number cols = 3; // Example value, adjust as needed

    // Ensure we have enough data for both matrices
    if (size < (rows * cols * sizeof(cmsFloat64Number))) {
        cmsDeleteContext(context);
        return 0;
    }

    const cmsFloat64Number *matrix = (const cmsFloat64Number *)data;
    const cmsFloat64Number *offset = (const cmsFloat64Number *)(data + (rows * cols * sizeof(cmsFloat64Number)));

    cmsStage *stage = cmsStageAllocMatrix(context, rows, cols, matrix, offset);

    if (stage != NULL) {
        cmsStageFree(stage);
    }

    cmsDeleteContext(context);
    return 0;
}