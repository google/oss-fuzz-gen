#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <aom/aom_codec.h>

extern "C" {
    #include <aom/aom.h>
}

extern "C" int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    // Initialize variables
    aom_codec_ctx_t codec_ctx;
    const char *option_name;
    const char *option_value;

    // Ensure size is sufficient for splitting into two strings
    if (size < 2) {
        return 0;
    }

    // Allocate memory for option_name and option_value
    size_t half_size = size / 2;
    option_name = static_cast<const char*>(malloc(half_size + 1));
    option_value = static_cast<const char*>(malloc(size - half_size + 1));

    // Copy data into option_name and option_value
    if (option_name && option_value) {
        memcpy((void*)option_name, data, half_size);
        memcpy((void*)option_value, data + half_size, size - half_size);

        // Null-terminate the strings
        ((char*)option_name)[half_size] = '\0';
        ((char*)option_value)[size - half_size] = '\0';

        // Call the function-under-test
        aom_codec_err_t result = aom_codec_set_option(&codec_ctx, option_name, option_value);

        // Free allocated memory
        free((void*)option_name);
        free((void*)option_value);
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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
