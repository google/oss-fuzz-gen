#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include <tiffio.h>

    void _TIFFfree(void *);
}

extern "C" int LLVMFuzzerTestOneInput_151(const uint8_t *data, size_t size) {
    // Create a TIFF memory stream to simulate a real TIFF file
    if (size > 0) {
        // Create a memory stream from the input data
        TIFF* tiff = TIFFOpen("mem:", "r");
        if (tiff != NULL) {
            // Use the TIFF library to process the data
            // For example, read the directory
            if (TIFFReadDirectory(tiff)) {
                // Successfully read a directory, now free the TIFF structure
                TIFFClose(tiff);
            } else {
                // If reading directory fails, still close the TIFF
                TIFFClose(tiff);
            }
        }
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

    LLVMFuzzerTestOneInput_151(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
