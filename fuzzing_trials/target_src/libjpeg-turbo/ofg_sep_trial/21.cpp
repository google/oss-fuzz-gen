#include <cstdint>
#include <cstdlib>
#include <cstdio>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    // Declare and initialize the variable to pass to tjGetScalingFactors
    int numScalingFactors = 0;

    // Call the function-under-test
    tjscalingfactor *scalingFactors = tjGetScalingFactors(&numScalingFactors);

    // Check if scalingFactors is not NULL and numScalingFactors is greater than 0
    if (scalingFactors != NULL && numScalingFactors > 0) {
        // Iterate over the scaling factors and print them (for debugging purposes)
        for (int i = 0; i < numScalingFactors; i++) {
            printf("Scaling Factor %d: %d/%d\n", i, scalingFactors[i].num, scalingFactors[i].denom);
        }
    }

    // Return 0 to indicate successful execution
    return 0;
}