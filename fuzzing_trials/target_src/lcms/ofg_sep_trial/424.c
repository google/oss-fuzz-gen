#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_424(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsUInt32Number rows = 3;
    cmsUInt32Number cols = 3;
    cmsFloat64Number matrix[9] = {1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0};
    cmsFloat64Number offset[3] = {0.0, 0.0, 0.0};

    if (size >= sizeof(cmsFloat64Number) * 12) {
        // Use data to fill matrix and offset if enough data is available
        for (size_t i = 0; i < 9; i++) {
            matrix[i] = ((cmsFloat64Number*)data)[i];
        }
        for (size_t i = 0; i < 3; i++) {
            offset[i] = ((cmsFloat64Number*)data)[9 + i];
        }
    }

    cmsStage *stage = cmsStageAllocMatrix(context, rows, cols, matrix, offset);

    if (stage != NULL) {
        cmsStageFree(stage);
    }

    cmsDeleteContext(context);

    return 0;
}