#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "vpx/vpx_decoder.h"
    #include "/src/libvpx/vpx/vpx_codec.h"
    #include "vpx/vp8dx.h"  // Include the header where vpx_codec_vp8_dx is declared
}

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    // Initialize the codec interface
    vpx_codec_iface_t *iface = vpx_codec_vp8_dx();

    // Ensure the data size is non-zero for valid input
    if (size == 0) {
        return 0;
    }

    // Initialize the codec stream info structure
    vpx_codec_stream_info_t stream_info;
    stream_info.sz = sizeof(vpx_codec_stream_info_t); // Set the size of the structure

    // Call the function under test
    vpx_codec_err_t result = vpx_codec_peek_stream_info(iface, data, (unsigned int)size, &stream_info);

    // The result can be used for further analysis or checks, if needed
    (void)result; // Suppress unused variable warning

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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
