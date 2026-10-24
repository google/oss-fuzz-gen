#include <stdint.h>
#include <stddef.h>
#include <aom/aom_decoder.h>
#include <aom/aomdx.h>
#include <string.h>

extern "C" {
    aom_codec_iface_t * aom_codec_av1_dx();
}

extern "C" int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    // Call the function-under-test
    aom_codec_iface_t *iface = aom_codec_av1_dx();

    // Check if the interface is not NULL
    if (iface != NULL) {
        aom_codec_ctx_t codec;
        aom_codec_err_t res;

        // Initialize the codec context
        res = aom_codec_dec_init(&codec, iface, NULL, 0);
        if (res == AOM_CODEC_OK) {
            // Decode the input data
            res = aom_codec_decode(&codec, data, size, NULL);
            if (res != AOM_CODEC_OK) {
                // Handle decode error if necessary
            }

            // Clean up
            aom_codec_destroy(&codec);
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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
