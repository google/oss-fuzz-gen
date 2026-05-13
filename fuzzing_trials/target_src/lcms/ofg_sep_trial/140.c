#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_140(const uint8_t *data, size_t size) {
    // Ensure there is enough data to form at least one cmsUInt16Number
    if (size < sizeof(cmsUInt16Number)) {
        return 0;
    }

    // Calculate the number of cmsUInt16Number elements we can create from the data
    size_t num_elements = size / sizeof(cmsUInt16Number);

    // Allocate memory for the cmsUInt16Number array
    cmsUInt16Number *alarmCodes = (cmsUInt16Number *)malloc(num_elements * sizeof(cmsUInt16Number));
    if (alarmCodes == NULL) {
        return 0;
    }

    // Copy data into the cmsUInt16Number array
    for (size_t i = 0; i < num_elements; i++) {
        alarmCodes[i] = ((cmsUInt16Number *)data)[i];
    }

    // Call the function-under-test
    cmsSetAlarmCodes(alarmCodes);

    // Free the allocated memory
    free(alarmCodes);

    return 0;
}