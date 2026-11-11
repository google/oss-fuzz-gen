#include <cstdint>
#include <cstdlib>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_140(const uint8_t *data, size_t size) {
    TIFF *tiff = TIFFOpen("/tmp/test.tiff", "w");
    if (tiff == NULL) {
        return 0;
    }

    // Ensure that thandle_t is not NULL. Use the data as a pointer.
    thandle_t clientdata = (thandle_t)data;

    // Call the function-under-test
    TIFFSetClientdata(tiff, clientdata);

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

    LLVMFuzzerTestOneInput_140(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
