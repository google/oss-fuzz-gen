#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_358(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to access required elements
    if (size < sizeof(cmsUInt32Number) + 6 * sizeof(cmsUInt16Number)) {
        return 0;
    }

    // Initialize variables
    cmsNAMEDCOLORLIST *namedColorList = cmsAllocNamedColorList(NULL, 1, 32, "Prefix", "Suffix");
    if (namedColorList == NULL) {
        return 0;
    }

    cmsUInt32Number index = *(cmsUInt32Number *)data;
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);

    char name[32];
    char prefix[32];
    char suffix[32];
    cmsUInt16Number pcs[3];
    cmsUInt16Number device[3];

    // Copy data into char arrays and cmsUInt16Number arrays
    strncpy(name, (const char *)data, sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0';
    data += sizeof(name);
    size -= sizeof(name);

    strncpy(prefix, (const char *)data, sizeof(prefix) - 1);
    prefix[sizeof(prefix) - 1] = '\0';
    data += sizeof(prefix);
    size -= sizeof(prefix);

    strncpy(suffix, (const char *)data, sizeof(suffix) - 1);
    suffix[sizeof(suffix) - 1] = '\0';
    data += sizeof(suffix);
    size -= sizeof(suffix);

    memcpy(pcs, data, sizeof(pcs));
    data += sizeof(pcs);
    size -= sizeof(pcs);

    memcpy(device, data, sizeof(device));

    // Call the function-under-test
    cmsBool result = cmsNamedColorInfo(namedColorList, index, name, prefix, suffix, pcs, device);

    // Clean up
    cmsFreeNamedColorList(namedColorList);

    return 0;
}