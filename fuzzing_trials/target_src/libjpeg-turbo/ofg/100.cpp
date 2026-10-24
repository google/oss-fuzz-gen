#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_100(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Not enough data to process
    }

    // Create a temporary file to write the input data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // Failed to create a temporary file
    }

    // Write the data to the temporary file
    if (write(fd, data, size) != static_cast<ssize_t>(size)) {
        close(fd);
        unlink(tmpl);
        return 0; // Failed to write data to the file
    }
    close(fd);

    // Initialize variables for tj3LoadImage16 function
    tjhandle handle = tjInitDecompress();
    if (!handle) {
        unlink(tmpl);
        return 0; // Failed to initialize TurboJPEG decompressor
    }

    int width = 0;
    int height = 0;
    int pixelFormat = TJPF_RGB;
    int flags = 0;

    // Call the function-under-test
    unsigned short *image = tj3LoadImage16(handle, tmpl, &width, pixelFormat, &height, &flags);

    // Clean up
    if (image) {
        tj3Free(image); // Correct function to free memory allocated by tj3LoadImage16
    }
    tjDestroy(handle);

    // Remove the temporary file
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

    LLVMFuzzerTestOneInput_100(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
