#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_141(const uint8_t *data, size_t size) {
    // Ensure we have enough data to form at least one cmsUInt16Number
    if (size < sizeof(cmsUInt16Number)) {
        return 0;
    }

    // Calculate the number of cmsUInt16Number elements we can form from the input data
    size_t num_elements = size / sizeof(cmsUInt16Number);

    // Allocate memory for the cmsUInt16Number array
    cmsUInt16Number *alarmCodes = (cmsUInt16Number *)malloc(num_elements * sizeof(cmsUInt16Number));
    if (alarmCodes == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Copy the input data into the cmsUInt16Number array
    memcpy(alarmCodes, data, num_elements * sizeof(cmsUInt16Number));

    // Call the function-under-test
    cmsSetAlarmCodes(alarmCodes);

    // Free the allocated memory
    free(alarmCodes);

    return 0;
}