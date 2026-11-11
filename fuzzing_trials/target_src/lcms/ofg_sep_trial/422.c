#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_422(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient for at least one RGB triplet
    if (size < 3) {
        return 0;
    }

    // Define the number of profiles
    cmsUInt32Number numProfiles = 2;
    
    // Allocate memory for the profile array
    cmsHPROFILE *profiles = (cmsHPROFILE *)malloc(numProfiles * sizeof(cmsHPROFILE));
    if (!profiles) {
        return 0;
    }

    // Initialize profiles with dummy profiles
    for (cmsUInt32Number i = 0; i < numProfiles; i++) {
        profiles[i] = cmsCreate_sRGBProfile();
        if (profiles[i] == NULL) {
            // Clean up and return if profile creation failed
            for (cmsUInt32Number j = 0; j < i; j++) {
                cmsCloseProfile(profiles[j]);
            }
            free(profiles);
            return 0;
        }
    }

    // Define other parameters for the transform
    cmsUInt32Number inputFormat = TYPE_RGB_8;
    cmsUInt32Number outputFormat = TYPE_RGB_8;
    cmsUInt32Number intent = INTENT_PERCEPTUAL;
    cmsUInt32Number flags = 0;

    // Call the function-under-test
    cmsHTRANSFORM transform = cmsCreateMultiprofileTransform(profiles, numProfiles, inputFormat, outputFormat, intent, flags);

    // Apply the transform to the input data
    if (transform != NULL) {
        // Prepare input and output buffers
        uint8_t input[3];
        uint8_t output[3];

        // Use the first three bytes of data as a single RGB triplet
        input[0] = data[0];
        input[1] = data[1];
        input[2] = data[2];

        // Perform the transformation
        cmsDoTransform(transform, input, output, 1);

        // Clean up the transform
        cmsDeleteTransform(transform);
    }

    // Clean up profiles
    for (cmsUInt32Number i = 0; i < numProfiles; i++) {
        cmsCloseProfile(profiles[i]);
    }
    free(profiles);

    return 0;
}