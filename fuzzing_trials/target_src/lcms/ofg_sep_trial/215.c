#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_215(const uint8_t *data, size_t size) {
    cmsToneCurve *toneCurve = NULL;
    cmsContext context = cmsCreateContext(NULL, NULL);

    if (size >= sizeof(cmsUInt16Number)) {
        cmsUInt16Number *curveData = (cmsUInt16Number *)malloc(size);
        if (curveData != NULL) {
            for (size_t i = 0; i < size / sizeof(cmsUInt16Number); i++) {
                curveData[i] = data[i % size];
            }

            toneCurve = cmsBuildTabulatedToneCurve16(context, size / sizeof(cmsUInt16Number), curveData);
            free(curveData);
        }
    }

    if (toneCurve != NULL) {
        cmsBool result = cmsIsToneCurveLinear(toneCurve);
        cmsFreeToneCurve(toneCurve);
    }

    cmsDeleteContext(context);
    return 0;
}