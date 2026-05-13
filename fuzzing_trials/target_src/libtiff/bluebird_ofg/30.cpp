#include <sys/stat.h>
#include <string.h>
extern "C" {
    #include "tiffio.h"
}

extern "C" int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    // Call the function-under-test
    TIFFCodec *codecs = TIFFGetConfiguredCODECs();

    // Since TIFFCodec does not have a 'next' member, we need to handle the codecs differently.
    // Assuming the codecs are stored in an array terminated by a codec with a NULL name.
    if (codecs != NULL) {
        for (TIFFCodec *codec = codecs; codec->name != NULL; codec++) {
            // Example operations on the codec
            if (codec->name != NULL) {
                // Print codec name and scheme
                printf("Codec Name: %s, Scheme: %d\n", codec->name, codec->scheme);
            }
        }

        // Free the codec list if necessary
        _TIFFfree(codecs);
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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
