#include <cstdint>
#include <cstddef>
#include <cstring>  // Include for memcpy

extern "C" {
    #include <aom/aom_codec.h>

    const char * aom_codec_error(const aom_codec_ctx_t *);
}

extern "C" int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size) {
    // Initialize aom_codec_ctx_t structure
    aom_codec_ctx_t codec_ctx;
    
    // Ensure codec_ctx is not NULL
    if (size < sizeof(aom_codec_ctx_t)) {
        return 0;
    }

    // Copy data into codec_ctx to simulate different inputs
    memcpy(&codec_ctx, data, sizeof(aom_codec_ctx_t));

    // Call the function-under-test
    const char *error_message = aom_codec_error(&codec_ctx);

    // Use the error_message in some way to avoid compiler optimizations
    if (error_message) {
        volatile const char *msg = error_message;
        (void)msg;
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

    LLVMFuzzerTestOneInput_56(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
