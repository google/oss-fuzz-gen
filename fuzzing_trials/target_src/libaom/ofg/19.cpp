#include <cstdint>
#include <cstddef>

extern "C" {
    #include <aom/aom_codec.h>
    #include <aom/aom_decoder.h>

    const char * aom_codec_iface_name(aom_codec_iface_t *);

    // Declare the function to obtain the AV1 decoder interface
    aom_codec_iface_t *aom_codec_av1_dx(void);
}

extern "C" int LLVMFuzzerTestOneInput_19(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to create a valid aom_codec_iface_t object
    // Note: We cannot use sizeof on an incomplete type, so we skip this check

    // Use a known valid codec interface
    aom_codec_iface_t *iface = aom_codec_av1_dx();

    // Call the function-under-test
    const char *name = aom_codec_iface_name(iface);

    // Use the result to prevent compiler optimizations
    if (name) {
        volatile const char *volatile_name = name;
        (void)volatile_name;
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

    LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
