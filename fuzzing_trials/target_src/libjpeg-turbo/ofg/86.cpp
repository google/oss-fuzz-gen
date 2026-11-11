#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_86(const uint8_t *data, size_t size) {
    // Initialize variables for tj3Transform
    tjhandle handle = tj3Init(TJINIT_TRANSFORM);
    if (handle == NULL) {
        return 0; // Handle initialization failure
    }

    int flags = 0; // No specific flags for now

    // Create an output buffer and its size
    unsigned char *outputBuffer = nullptr;
    size_t outputSize = 0;

    // Initialize a tjtransform structure
    tjtransform transform;
    transform.op = TJXOP_NONE; // No transformation operations
    transform.options = 0;
    transform.data = NULL;
    transform.customFilter = NULL;

    // Call the function-under-test
    int result = tj3Transform(handle, data, size, flags, &outputBuffer, &outputSize, &transform);

    // Clean up
    if (outputBuffer != nullptr) {
        tj3Free(outputBuffer);
    }
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

    LLVMFuzzerTestOneInput_86(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
