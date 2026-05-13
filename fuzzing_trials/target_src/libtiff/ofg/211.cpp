#include <cstdint>
#include <cstdlib>
#include <unistd.h>  // Include this for close, write, and unlink functions
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_211(const uint8_t *data, size_t size) {
    TIFF *tiff = nullptr;
    uint32_t strileIndex = 0;

    // Create a temporary file to store the TIFF data
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

    // Close the file descriptor to flush data
    close(fd);

    // Open the TIFF file
    tiff = TIFFOpen(tmpl, "r");
    if (tiff == nullptr) {
        return 0;
    }

    // Fuzz the TIFFGetStrileOffset function with different strileIndex values
    for (uint32_t i = 0; i < 10; ++i) {
        strileIndex = i;
        uint64_t offset = TIFFGetStrileOffset(tiff, strileIndex);
        (void)offset; // Use the offset to avoid unused variable warning
    }

    // Close the TIFF file
    TIFFClose(tiff);

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

    LLVMFuzzerTestOneInput_211(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
