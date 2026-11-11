#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    // Initialize a non-null integer pointer
    int numScalingFactors = 0;
    int *numPtr = &numScalingFactors;

    // Call the function-under-test
    tjscalingfactor *scalingFactors = tj3GetScalingFactors(numPtr);

    // Ensure that scalingFactors is not NULL and numScalingFactors is greater than 0
    if (scalingFactors != NULL && numScalingFactors > 0) {
        // Iterate through the scaling factors and print them (for debugging purposes)
        for (int i = 0; i < numScalingFactors; ++i) {
            printf("Scaling Factor %d: %d/%d\n", i, scalingFactors[i].num, scalingFactors[i].denom);
        }
    }

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
