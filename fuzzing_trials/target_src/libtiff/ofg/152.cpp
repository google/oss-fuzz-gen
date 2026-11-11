#include <cstdint>
#include <cstdio>
#include <cstring>

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_152(const uint8_t *data, size_t size) {
    // Create a TIFF structure
    TIFF *tiff = TIFFOpen("dummy.tiff", "w");
    if (tiff == nullptr) {
        return 0;
    }

    // Create a non-null string for the module and format
    const char *module = "fuzz_module";
    const char *format = "fuzz_format";

    // Use the first byte of data to create a non-null pointer
    void *client_data = (void*)data;

    // Call the function-under-test
    TIFFWarningExtR(tiff, module, format, client_data);

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

    LLVMFuzzerTestOneInput_152(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
