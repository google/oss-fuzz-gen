#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include this for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_158(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Interpret the first bytes of `data` as a cmsFloat64Number
    cmsFloat64Number adaptationState;
    memcpy(&adaptationState, data, sizeof(cmsFloat64Number));

    // Call the function-under-test
    cmsFloat64Number result = cmsSetAdaptationState(adaptationState);

    // Use the result in some way to avoid compiler optimizations removing the call
    volatile cmsFloat64Number use_result = result;
    (void)use_result;

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_158(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
