#include <cstdint>
#include <cstdlib>
#include <cstdio>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_85(const uint8_t *data, size_t size) {
    // Declare and initialize the integer variable to be passed to the function
    int numScalingFactors = 0;

    // Call the function-under-test
    tjscalingfactor *scalingFactors = tj3GetScalingFactors(&numScalingFactors);

    // Check if the function returned a valid pointer
    if (scalingFactors != nullptr && numScalingFactors > 0) {
        // Iterate over the scaling factors and print them (for debugging purposes)
        for (int i = 0; i < numScalingFactors; ++i) {
            printf("Scaling Factor %d: %d/%d\n", i, scalingFactors[i].num, scalingFactors[i].denom);
        }
    }

    // Return 0 to indicate successful execution
    return 0;
}