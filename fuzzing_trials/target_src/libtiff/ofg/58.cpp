#include <stdint.h>
#include <stddef.h>
#include <tiffio.h>
#include <stdio.h>

extern "C" int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size) {
    // Write data to a temporary file
    FILE *file = fopen("/tmp/fuzzfile.tiff", "wb");
    if (file == NULL) {
        return 0;
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the TIFF file for reading
    TIFF *tiff = TIFFOpen("/tmp/fuzzfile.tiff", "r");
    if (tiff == NULL) {
        return 0;
    }

    // Ensure the file descriptor is not NULL and within a reasonable range
    int fd = TIFFFileno(tiff); // Get the actual file descriptor

    // Call the function-under-test
    TIFFSetFileno(tiff, fd);

    // Close the TIFF object
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

    LLVMFuzzerTestOneInput_58(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
