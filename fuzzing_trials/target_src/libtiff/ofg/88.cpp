#include <cstdint>
#include <cstdio>
#include <unistd.h>  // Include for close(), write(), and mkstemp()
#include <cstdlib>   // Include for remove()

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_88(const uint8_t *data, size_t size) {
    TIFF *tiff;
    uint32_t sample = 1; // Initialize with a non-zero value

    // Create a temporary file to hold the data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the data to the temporary file
    if (write(fd, data, size) != static_cast<ssize_t>(size)) {
        close(fd);
        return 0;
    }

    // Close the file descriptor
    close(fd);

    // Open the TIFF file from the temporary file
    tiff = TIFFOpen(tmpl, "r");
    if (tiff == nullptr) {
        return 0;
    }

    // Call the function-under-test
    uint64_t stripSize = TIFFVStripSize64(tiff, sample);

    // Clean up
    TIFFClose(tiff);
    remove(tmpl);

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

    LLVMFuzzerTestOneInput_88(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
