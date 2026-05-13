#include <cstdint>
#include <cstdlib>
#include <aom/aom_codec.h>

extern "C" {
    #include <aom/aom_codec.h>
}

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    // Initialize aom_codec_iface_t pointer
    const aom_codec_iface_t *iface = nullptr;

    // Since we cannot use sizeof on an incomplete type, we assume the size is always sufficient for fuzzing
    if (size > 0) {
        // Cast the data to aom_codec_iface_t pointer
        iface = reinterpret_cast<const aom_codec_iface_t *>(data);
    } else {
        // If size is too small, return early
        return 0;
    }

    // Call the function-under-test
    aom_codec_caps_t caps = aom_codec_get_caps(iface);

    // Use the result in some way (e.g., print it, though not necessary for fuzzing)
    (void)caps; // Suppress unused variable warning

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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
