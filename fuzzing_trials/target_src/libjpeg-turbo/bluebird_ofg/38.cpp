#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>  // For malloc and free

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "../src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_38(const uint8_t *data, size_t size) {
    // Initialize the TurboJPEG transformer handle
    tjhandle handle = tjInitTransform();
    
    // Check if the handle was initialized correctly
    if (handle == NULL) {
        return 0;
    }

    // Allocate output buffer
    unsigned char *jpegBuf = NULL;
    unsigned long jpegSize = 0;

    // Define a tjtransform structure
    tjtransform transform;
    transform.op = TJXOP_NONE;
    transform.options = 0;
    transform.data = NULL;
    transform.customFilter = NULL;

    // Attempt to transform the input data
    int transformResult = tjTransform(handle, data, size, 1, &jpegBuf, &jpegSize, &transform, 0);

    // Free the output buffer if it was allocated
    if (jpegBuf != NULL) {
        tjFree(jpegBuf);
    }

    // Clean up the TurboJPEG transformer handle
    tjDestroy(handle);

    // Return 0 to indicate the fuzzer should continue
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

    LLVMFuzzerTestOneInput_38(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
