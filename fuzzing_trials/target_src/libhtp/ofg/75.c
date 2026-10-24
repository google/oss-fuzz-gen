#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libhtp/htp/htp.h"

int LLVMFuzzerTestOneInput_75(const uint8_t *data, size_t size) {
    // Initialize the configuration object
    htp_cfg_t *cfg = htp_config_create();
    if (cfg == NULL) {
        return 0;
    }

    // Initialize the decoder context using the correct enum tag
    enum htp_decoder_ctx_t decoder_ctx = HTP_DECODER_URLENCODED;

    // Initialize the bstr object
    bstr *input_bstr = bstr_dup_mem((const char *)data, size);
    if (input_bstr == NULL) {
        htp_config_destroy(cfg);
        return 0;
    }

    // Initialize the uint64_t variable
    uint64_t input_len = size;

    // Call the function-under-test
    htp_status_t status = htp_urldecode_inplace(cfg, decoder_ctx, input_bstr, &input_len);

    // Clean up
    bstr_free(input_bstr);
    htp_config_destroy(cfg);

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

    LLVMFuzzerTestOneInput_75(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
