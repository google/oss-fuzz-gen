#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h> // for close()
#include <sys/types.h> // for size_t

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    tjhandle handle = NULL;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    const char *filename = tmpl;
    unsigned short *imageBuffer = NULL; // Use unsigned short for J16SAMPLE
    int width = 1;
    int height = 1;
    int pitch = 1;
    int flags = 0;

    if (size < sizeof(unsigned short)) {
        close(fd);
        return 0;
    }

    // Initialize TurboJPEG handle
    handle = tjInitCompress();
    if (!handle) {
        close(fd);
        return 0;
    }

    // Allocate memory for image buffer
    imageBuffer = (unsigned short *)malloc(size);
    if (!imageBuffer) {
        tjDestroy(handle);
        close(fd);
        return 0;
    }

    // Copy data to image buffer
    memcpy(imageBuffer, data, size);

    // Call the function-under-test
    tj3SaveImage16(handle, filename, imageBuffer, width, pitch, height, flags);

    // Clean up
    free(imageBuffer);
    tjDestroy(handle);
    close(fd);

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

    LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
