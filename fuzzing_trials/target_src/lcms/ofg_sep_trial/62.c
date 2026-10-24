#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>
#include <string.h>  // For memcpy

int LLVMFuzzerTestOneInput_62(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsContext context = (cmsContext)1;  // Non-NULL context
    cmsUInt32Number nSegments = 1;  // Number of segments
    cmsCurveSegment segment;  // A single curve segment
    cmsCurveSegment* segments = &segment;  // Pointer to the segment

    // Initialize the segment with some default values
    segment.SampledPoints = NULL;
    segment.nGridPoints = 0;
    segment.Type = 0;  // Assuming a valid segment type
    memset(segment.Params, 0, sizeof(segment.Params));  // Initialize Params array to zero

    // Check if the input data is sufficient to be used
    if (size < sizeof(cmsFloat64Number)) {
        return 0;  // Not enough data to proceed
    }

    // Use the input data to initialize the segment's parameter
    cmsFloat64Number param = *((cmsFloat64Number*)data);
    memcpy(segment.Params, &param, sizeof(cmsFloat64Number));  // Copy the parameter into the Params array

    // Call the function-under-test
    cmsToneCurve* toneCurve = cmsBuildSegmentedToneCurve(context, nSegments, segments);

    // Clean up
    if (toneCurve != NULL) {
        cmsFreeToneCurve(toneCurve);
    }

    return 0;
}