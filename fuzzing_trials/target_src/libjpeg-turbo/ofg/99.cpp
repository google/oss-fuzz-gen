#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h> // For close() and unlink()

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"

    unsigned short * tj3LoadImage16(tjhandle handle, const char *filename, int *width, int align, int *height, int *pixelFormat);
    void tjFree(unsigned char *buffer); // Corrected declaration for tjFree to match the actual function signature
}

extern "C" int LLVMFuzzerTestOneInput_99(const uint8_t *data, size_t size) {
    // Create a temporary file to write the fuzzing data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }
    close(fd);

    // Initialize TurboJPEG handle
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        unlink(tmpl);
        return 0;
    }

    // Prepare variables for the function call
    int width = 0;
    int height = 0;
    int pixelFormat = TJPF_RGB; // Using a valid pixel format
    int align = 4; // Common alignment value

    // Call the function-under-test
    unsigned short *image = tj3LoadImage16(handle, tmpl, &width, align, &height, &pixelFormat);

    // Clean up
    if (image != nullptr) {
        tjFree(reinterpret_cast<unsigned char *>(image)); // Cast to match the function signature
    }
    tjDestroy(handle);
    unlink(tmpl);

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

    LLVMFuzzerTestOneInput_99(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
