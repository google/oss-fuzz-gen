#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h> // For close and unlink
#include <fcntl.h> // For mkstemp
#include <sys/types.h>
#include <sys/stat.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"

    unsigned short * tj3LoadImage16(tjhandle handle, const char *filename, int *width, int pitch, int *height, int *pixelFormat);
    void tjFree(unsigned char *buffer); // Correct signature for tjFree
}

extern "C" int LLVMFuzzerTestOneInput_117(const uint8_t *data, size_t size) {
    // Ensure there's at least a minimal amount of data to form a valid image
    if (size < 100) return 0; // Adjust this threshold based on expected minimal valid image size

    // Create a temporary file to write the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) return 0; // Failed to create temp file

    // Write data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);
        return 0; // Failed to write data
    }
    close(fd);

    // Initialize variables for the function call
    tjhandle handle = tjInitDecompress();
    if (!handle) {
        unlink(tmpl);
        return 0; // Failed to initialize TurboJPEG decompressor
    }

    int width = 0;
    int height = 0;
    int pixelFormat = TJPF_RGB; // Set a default pixel format
    int pitch = 0; // Set pitch to 0 for default calculation

    // Call the function-under-test
    unsigned short *image = tj3LoadImage16(handle, tmpl, &width, pitch, &height, &pixelFormat);

    // Check if the image was successfully loaded
    if (image) {
        // Log or assert to verify the function is being exercised
        printf("Image loaded: width=%d, height=%d, pixelFormat=%d\n", width, height, pixelFormat);

        // Optionally, add further processing here to ensure the function is behaving as expected
        tjFree(reinterpret_cast<unsigned char*>(image)); // Correct conversion for tjFree
    } else {
        printf("Failed to load image from data of size %zu\n", size);
    }

    tjDestroy(handle);
    unlink(tmpl); // Clean up the temporary file

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

    LLVMFuzzerTestOneInput_117(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
