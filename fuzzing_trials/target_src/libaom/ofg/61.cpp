#include <stdint.h>
#include <stddef.h>
#include <aom/aom_codec.h>

extern "C" int LLVMFuzzerTestOneInput_61(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract an aom_codec_err_t value
    if (size < sizeof(aom_codec_err_t)) {
        return 0;
    }

    // Cast the input data to aom_codec_err_t
    aom_codec_err_t err = *(reinterpret_cast<const aom_codec_err_t *>(data));

    // Call the function-under-test
    const char *error_string = aom_codec_err_to_string(err);

    // Use the error_string in some way to ensure it is not optimized away
    if (error_string) {
        volatile const char *volatile_string = error_string;
        (void)volatile_string;
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

    LLVMFuzzerTestOneInput_61(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
