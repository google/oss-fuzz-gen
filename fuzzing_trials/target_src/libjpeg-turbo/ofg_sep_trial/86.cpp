#include <cstdint>
#include <cstdlib>
#include <iostream>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_86(const uint8_t *data, size_t size) {
    // Declare and initialize the integer pointer
    int numScalingFactors = 0;
    int *numScalingFactorsPtr = &numScalingFactors;

    // Call the function-under-test
    tjscalingfactor *scalingFactors = tj3GetScalingFactors(numScalingFactorsPtr);

    // Check if the function returned a non-NULL pointer
    if (scalingFactors != NULL && numScalingFactors > 0) {
        // Iterate over the scaling factors and print them
        for (int i = 0; i < numScalingFactors; i++) {
            std::cout << "Scaling Factor " << i << ": "
                      << scalingFactors[i].num << "/"
                      << scalingFactors[i].denom << std::endl;
        }
    }

    return 0;
}