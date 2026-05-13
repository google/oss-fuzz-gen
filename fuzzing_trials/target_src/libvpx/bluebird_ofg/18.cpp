#include <sys/stat.h>
#include <string.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include "/src/libvpx/vpx/vpx_codec.h"
#include "/src/libvpx/vpx/vpx_encoder.h"

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    vpx_codec_ctx_t codec_ctx;
    vpx_fixed_buf_t fixed_buf;
    vpx_codec_err_t err;
    unsigned int pad_before = 0;
    unsigned int pad_after = 0;

    // Initialize codec context
    memset(&codec_ctx, 0, sizeof(codec_ctx));

    // Initialize fixed buffer with the input data
    fixed_buf.buf = (void *)data;
    fixed_buf.sz = size;

    // Call the function-under-test
    err = vpx_codec_set_cx_data_buf(&codec_ctx, &fixed_buf, pad_before, pad_after);

    // Ensure the function is called
    (void)err;

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

    LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
