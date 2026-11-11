#include <cstdint>
#include <tiffio.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_137(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a TIFF structure and a tag
    if (size < sizeof(uint32_t) + sizeof(uint32_t)) {
        return 0;
    }

    // Create a temporary file to hold the TIFF data
    FILE* tempFile = std::tmpfile();
    if (!tempFile) {
        return 0;
    }

    // Write the input data to the temporary file
    if (fwrite(data, 1, size, tempFile) != size) {
        fclose(tempFile);
        return 0;
    }

    // Rewind the file to the beginning
    rewind(tempFile);

    // Initialize TIFF structure
    TIFF* tiff = TIFFFdOpen(fileno(tempFile), "temp.tiff", "r");
    if (!tiff) {
        fclose(tempFile);
        return 0;
    }

    // Extract a uint32_t tag from the input data
    uint32_t tag = *reinterpret_cast<const uint32_t*>(data);

    // Call the function-under-test
    const TIFFField* field = TIFFFieldWithTag(tiff, tag);

    // Clean up
    TIFFClose(tiff);
    fclose(tempFile);

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

    LLVMFuzzerTestOneInput_137(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
