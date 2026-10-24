#include <cstdint>
#include <cstdlib>
#include <cstring> // Include this header for memcpy

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_244(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient for a minimal TIFF header
    if (size < 8) {
        return 0;
    }

    // Create a temporary file to write the input data
    const char *filename = "/tmp/fuzz.tiff";
    FILE *file = fopen(filename, "wb");
    if (!file) {
        return 0;
    }

    // Write the input data to the file
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the TIFF file
    TIFF *tiff = TIFFOpen(filename, "r");
    if (tiff == nullptr) {
        return 0;
    }

    // Read the TIFF directory
    if (TIFFReadDirectory(tiff)) {
        // Optionally, you can add more TIFF processing here
    }

    // Cleanup
    TIFFClose(tiff);

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

    LLVMFuzzerTestOneInput_244(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
