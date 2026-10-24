#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include this for memcpy

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_249(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for a minimal valid TIFF header
    if (size < 8) { // TIFF header is typically 8 bytes
        return 0;
    }

    // Open a memory-mapped TIFF file from the input data
    TIFF* tiff = TIFFClientOpen("memory", "r", (thandle_t)data,
                                [](thandle_t fd, void* buf, tmsize_t size) -> tmsize_t {
                                    memcpy(buf, (void*)fd, size);
                                    return size;
                                },
                                [](thandle_t fd, void* buf, tmsize_t size) -> tmsize_t {
                                    return 0;
                                },
                                [](thandle_t fd, toff_t off, int whence) -> toff_t {
                                    return 0;
                                },
                                [](thandle_t fd) -> int {
                                    return 0;
                                },
                                [](thandle_t fd) -> toff_t {
                                    return 0;
                                },
                                [](thandle_t fd, void** pbase, toff_t* psize) -> int {
                                    return 0;
                                },
                                [](thandle_t fd, void* base, toff_t size) -> void {
                                });

    if (tiff) {
        // Initialize a variable for the strip index
        uint32_t stripIndex = 0;

        // Call the function-under-test
        uint64_t stripSize = TIFFRawStripSize64(tiff, stripIndex);

        // Use the result in some way to avoid compiler optimizations
        (void)stripSize;

        // Close the TIFF file
        TIFFClose(tiff);
    }

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

    LLVMFuzzerTestOneInput_249(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
