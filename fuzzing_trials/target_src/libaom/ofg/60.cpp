#include <stdint.h>
#include <stddef.h>
#include <aom/aom_codec.h>

extern "C" int LLVMFuzzerTestOneInput_60(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract an aom_codec_err_t value
    if (size < sizeof(aom_codec_err_t)) {
        return 0;
    }

    // Extract an aom_codec_err_t value from the input data
    aom_codec_err_t err = *(reinterpret_cast<const aom_codec_err_t*>(data));

    // Call the function-under-test
    const char *error_string = aom_codec_err_to_string(err);

    // Use the result to avoid compiler optimizations that may remove the call
    if (error_string) {
        // Do something trivial with error_string
        volatile char c = error_string[0];
        (void)c;
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

    LLVMFuzzerTestOneInput_60(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
