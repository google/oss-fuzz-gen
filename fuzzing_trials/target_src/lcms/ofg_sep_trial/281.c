#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_281(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for at least one cmsUInt16Number
    if (size < sizeof(cmsUInt16Number)) {
        return 0;
    }

    // Initialize the context
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Prepare the cmsUInt16Number array
    size_t num_elements = size / sizeof(cmsUInt16Number);
    cmsUInt16Number *alarmCodes = (cmsUInt16Number *)data;

    // Call the function-under-test
    cmsSetAlarmCodesTHR(context, alarmCodes);

    // Clean up the context
    cmsDeleteContext(context);

    return 0;
}