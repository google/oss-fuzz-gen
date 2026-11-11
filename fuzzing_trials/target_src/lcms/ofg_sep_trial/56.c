#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsUInt32Number) * 3 + sizeof(cmsFloat64Number) * 4) {
        return 0;
    }

    const cmsUInt32Number *uint32_data = (const cmsUInt32Number *)data;
    const cmsFloat64Number *float64_data = (const cmsFloat64Number *)(data + sizeof(cmsUInt32Number) * 3);

    cmsUInt32Number param1 = uint32_data[0];
    cmsFloat64Number param2 = float64_data[0];
    cmsFloat64Number param3 = float64_data[1];
    cmsFloat64Number param4 = float64_data[2];
    cmsFloat64Number param5 = float64_data[3];
    cmsUInt32Number param6 = uint32_data[1];
    cmsUInt32Number param7 = uint32_data[2];

    cmsHPROFILE profile = cmsCreateBCHSWabstractProfile(param1, param2, param3, param4, param5, param6, param7);

    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    return 0;
}