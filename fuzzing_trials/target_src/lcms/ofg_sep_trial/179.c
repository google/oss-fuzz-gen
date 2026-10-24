#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_179(const uint8_t *data, size_t size) {
    // Ensure there's enough data for meaningful operation
    if (size < 3) {
        return 0;
    }

    // Initialize all variables before using them
    cmsHPROFILE inputProfile = NULL;
    cmsHPROFILE outputProfile = NULL;
    cmsHPROFILE proofingProfile = NULL;
    cmsUInt32Number inputFormat = TYPE_RGB_8;
    cmsUInt32Number outputFormat = TYPE_RGB_8;
    cmsUInt32Number proofingIntent = INTENT_RELATIVE_COLORIMETRIC;
    cmsUInt32Number flags = 0;
    cmsHTRANSFORM transform = NULL;

    // Create profiles based on input data
    inputProfile = cmsCreate_sRGBProfile();
    outputProfile = cmsCreate_sRGBProfile();
    proofingProfile = cmsCreate_sRGBProfile();

    // Use input data to modify the formats and intents
    inputFormat = data[0] % 256;  // Example: Use first byte for input format
    outputFormat = data[1] % 256; // Example: Use second byte for output format
    proofingIntent = data[2] % 4; // Example: Use third byte for proofing intent

    // Call the function-under-test with fuzzed parameters
    transform = cmsCreateProofingTransform(inputProfile, inputFormat, outputProfile, outputFormat, proofingProfile, proofingIntent, INTENT_RELATIVE_COLORIMETRIC, flags);

    // Clean up
    if (transform != NULL) {
        cmsDeleteTransform(transform);
    }
    if (inputProfile != NULL) {
        cmsCloseProfile(inputProfile);
    }
    if (outputProfile != NULL) {
        cmsCloseProfile(outputProfile);
    }
    if (proofingProfile != NULL) {
        cmsCloseProfile(proofingProfile);
    }

    return 0;
}