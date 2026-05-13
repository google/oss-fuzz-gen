#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_204(const uint8_t *data, size_t size) {
    cmsHTRANSFORM handle;
    cmsCIELab labPoint;
    cmsBool result;

    // Initialize the cmsHTRANSFORM
    handle = cmsCreateTransform(NULL, TYPE_Lab_DBL, NULL, TYPE_Lab_DBL, INTENT_PERCEPTUAL, 0);
    if (handle == NULL) {
        return 0;
    }

    // Ensure size is sufficient to extract a cmsCIELab structure
    if (size < 3) { // Use 3 instead of sizeof(cmsCIELab) since we are manually filling labPoint
        cmsDeleteTransform(handle);
        return 0;
    }

    // Initialize cmsCIELab with data from the input
    labPoint.L = ((double)data[0]) / 255.0 * 100.0; // Scale to 0-100 for L
    labPoint.a = ((double)data[1]) - 128.0;         // Center a around 0
    labPoint.b = ((double)data[2]) - 128.0;         // Center b around 0

    // Call the function under test
    result = cmsGDBAddPoint(handle, &labPoint);

    // Clean up
    cmsDeleteTransform(handle);

    return 0;
}