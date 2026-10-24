#include <stdint.h>
#include <stdlib.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    tjhandle handle = tj3Init(TJINIT_DECOMPRESS);
    if (handle == NULL) {
        return 0;
    }

    // Ensure that size is sufficient for two integers
    if (size < 2 * sizeof(int)) {
        tj3Destroy(handle);
        return 0;
    }

    // Extract two integers from the input data
    int num = ((int *)data)[0];
    int denom = ((int *)data)[1];

    // Ensure denominator is not zero to avoid division by zero
    if (denom == 0) {
        denom = 1;
    }

    // Create a scaling factor
    tjscalingfactor scalingFactor = { num, denom };

    // Call the function-under-test
    tj3SetScalingFactor(handle, scalingFactor);

    // Clean up
    tj3Destroy(handle);

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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
