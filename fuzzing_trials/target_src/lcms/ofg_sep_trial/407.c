#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_407(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsCIEXYZ dest;
    cmsCIEXYZ source;
    cmsCIEXYZ illuminant;
    cmsCIEXYZ adaptedIlluminant;

    // Ensure the data size is sufficient to populate the cmsCIEXYZ structures
    if (size < sizeof(cmsCIEXYZ) * 4) {
        return 0;
    }

    // Populate the cmsCIEXYZ structures with data
    dest.X = *(const double*)(data);
    dest.Y = *(const double*)(data + sizeof(double));
    dest.Z = *(const double*)(data + 2 * sizeof(double));

    source.X = *(const double*)(data + 3 * sizeof(double));
    source.Y = *(const double*)(data + 4 * sizeof(double));
    source.Z = *(const double*)(data + 5 * sizeof(double));

    illuminant.X = *(const double*)(data + 6 * sizeof(double));
    illuminant.Y = *(const double*)(data + 7 * sizeof(double));
    illuminant.Z = *(const double*)(data + 8 * sizeof(double));

    adaptedIlluminant.X = *(const double*)(data + 9 * sizeof(double));
    adaptedIlluminant.Y = *(const double*)(data + 10 * sizeof(double));
    adaptedIlluminant.Z = *(const double*)(data + 11 * sizeof(double));

    // Call the function-under-test
    cmsBool result = cmsAdaptToIlluminant(&dest, &source, &illuminant, &adaptedIlluminant);

    // Use the result to avoid compiler optimizations
    (void)result;

    return 0;
}