#include <string.h>
#include <sys/stat.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include "/src/aom/aom/aom_codec.h"

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    // Initialize the codec context
    aom_codec_ctx_t codec_ctx;
    memset(&codec_ctx, 0, sizeof(codec_ctx));

    // Ensure size is large enough to split into two strings
    if (size < 2) {
        return 0;
    }

    // Split the input data into two strings
    size_t half_size = size / 2;
    const char *option_name = reinterpret_cast<const char *>(data);
    const char *option_value = reinterpret_cast<const char *>(data + half_size);

    // Ensure the strings are null-terminated
    char option_name_buf[256];
    char option_value_buf[256];
    size_t option_name_len = half_size < 255 ? half_size : 255;
    size_t option_value_len = (size - half_size) < 255 ? (size - half_size) : 255;

    strncpy(option_name_buf, option_name, option_name_len);
    option_name_buf[option_name_len] = '\0';

    strncpy(option_value_buf, option_value, option_value_len);
    option_value_buf[option_value_len] = '\0';

    // Call the function under test
    aom_codec_err_t result = aom_codec_set_option(&codec_ctx, option_name_buf, option_value_buf);

    // Return 0 to indicate that the fuzzer should continue
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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
