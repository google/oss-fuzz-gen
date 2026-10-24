extern "C" {
    #include <tiffio.h>
    #include <cstdint>
    #include <cstdlib>
    #include <cstdio>
}

extern "C" int LLVMFuzzerTestOneInput_139(const uint8_t *data, size_t size) {
    TIFF *tiff = nullptr;
    thandle_t clientData = reinterpret_cast<thandle_t>(1); // Initialize with a non-null value

    // Create a temporary TIFF file to avoid passing a null TIFF pointer
    const char *filename = "/tmp/fuzz_tiff.tif";
    FILE *file = fopen(filename, "wb+");
    if (file == nullptr) {
        return 0;
    }

    // Write the fuzzing input data into the TIFF file
    if (fwrite(data, 1, size, file) != size) {
        fclose(file);
        return 0;
    }
    fclose(file);

    // Open the TIFF file
    tiff = TIFFOpen(filename, "r+");
    if (tiff == nullptr) {
        return 0;
    }

    // Call the function-under-test
    TIFFSetClientdata(tiff, clientData);

    // Close the TIFF file
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

    LLVMFuzzerTestOneInput_139(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
