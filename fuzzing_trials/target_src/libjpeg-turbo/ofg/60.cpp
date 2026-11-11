#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_60(const uint8_t *data, size_t size) {
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0; // If initialization fails, exit early
    }

    // Allocate memory for the dimensions and subsampling variables
    int width = 0, height = 0, subsamp = 0;

    // Ensure the data is not null and has a reasonable size
    if (data != nullptr && size > 0) {
        // Copy the input data to a mutable buffer
        unsigned char *buffer = (unsigned char *)malloc(size);
        if (buffer == nullptr) {
            tjDestroy(handle);
            return 0; // If memory allocation fails, exit early
        }
        memcpy(buffer, data, size);

        // Call the function-under-test
        tjDecompressHeader2(handle, buffer, (unsigned long)size, &width, &height, &subsamp);

        // Free the allocated buffer
        free(buffer);
    }

    // Clean up the TurboJPEG handle
    tjDestroy(handle);
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

    LLVMFuzzerTestOneInput_60(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
