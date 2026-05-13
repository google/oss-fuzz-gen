#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    int numScalingFactors = 0;
    
    // Call the function-under-test
    tjscalingfactor *scalingFactors = tjGetScalingFactors(&numScalingFactors);
    
    // Use the scaling factors in some way to ensure they are accessed
    if (scalingFactors != NULL && numScalingFactors > 0) {
        for (int i = 0; i < numScalingFactors; i++) {
            // Access each scaling factor
            int num = scalingFactors[i].num;
            int denom = scalingFactors[i].denom;
            
            // Perform some operation to ensure they are used
            if (denom != 0) {
                double scale = static_cast<double>(num) / denom;
                (void)scale; // Suppress unused variable warning
            }
        }
    }

    return 0;
}