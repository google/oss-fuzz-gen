#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include <aom/aom_codec.h>
    #include <aom/aom_decoder.h>
    #include <aom/aomdx.h> // Include the header for AV1 decoder interface
}

extern "C" int LLVMFuzzerTestOneInput_29(const uint8_t *data, size_t size) {
    // Declare and initialize the necessary variables
    aom_codec_iface_t *iface = aom_codec_av1_dx();  // Use AV1 decoder interface
    aom_codec_stream_info_t stream_info;
    aom_codec_err_t result;

    // Ensure the stream_info is properly initialized
    stream_info.is_annexb = 0; // Initialize is_annexb as part of stream_info

    // Call the function-under-test
    result = aom_codec_peek_stream_info(iface, data, size, &stream_info);

    // Return 0 to indicate the fuzzer should continue
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

    LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
