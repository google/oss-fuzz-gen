#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_74(const uint8_t *data, size_t size) {
    cmsHTRANSFORM transform;
    cmsNAMEDCOLORLIST *namedColorList;

    // Initialize the Little CMS library
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Ensure that the data size is sufficient for creating a transform
    if (size < sizeof(cmsCIEXYZ)) {
        cmsDeleteContext(context);
        return 0;
    }

    // Create a color transform using the data as part of the creation process
    cmsHPROFILE inputProfile = cmsCreateXYZProfile();
    cmsHPROFILE outputProfile = cmsCreate_sRGBProfile();
    transform = cmsCreateTransform(inputProfile, TYPE_XYZ_DBL, outputProfile, TYPE_RGB_DBL, INTENT_PERCEPTUAL, 0);

    // Call the function under test
    namedColorList = cmsGetNamedColorList(transform);

    // Clean up
    cmsDeleteTransform(transform);
    cmsCloseProfile(inputProfile);
    cmsCloseProfile(outputProfile);
    cmsDeleteContext(context);

    return 0;
}