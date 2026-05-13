#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // Include for close() and remove()

extern "C" {
    #include "../src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/jpeglib.h"  // Include for J16SAMPLE
}

extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for the parameters
    if (size < 10) return 0;

    // Create a temporary file to use as the image path
    char tmpl[] = "/tmp/fuzzimageXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) return 0;
    close(fd);

    // Initialize tjhandle
    tjhandle handle = tjInitCompress();

    // Extract parameters from data
    int width = (int)data[0] + 1;  // Ensure width is non-zero
    int height = (int)data[1] + 1; // Ensure height is non-zero
    int pitch = (int)data[2] + 1;  // Ensure pitch is non-zero
    int flags = (int)data[3];

    // Allocate memory for the J16SAMPLE input
    size_t sampleSize = width * height * sizeof(J16SAMPLE);
    J16SAMPLE *samples = (J16SAMPLE *)malloc(sampleSize);
    if (!samples) {
        tjDestroy(handle);
        remove(tmpl);
        return 0;
    }

    // Ensure the provided data is large enough to fill the samples
    if (size < 10 + sampleSize) {
        free(samples);
        tjDestroy(handle);
        remove(tmpl);
        return 0;
    }

    // Fill the samples with data
    memcpy(samples, data + 10, sampleSize);

    // Call the function-under-test
    int result = tj3SaveImage16(handle, tmpl, samples, width, height, pitch, flags);

    // Clean up
    free(samples);
    tjDestroy(handle);
    remove(tmpl);

    return result;
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

    LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
