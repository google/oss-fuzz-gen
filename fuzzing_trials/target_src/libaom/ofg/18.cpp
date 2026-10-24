#include <cstdint>
#include <cstddef>
#include <aom/aom_codec.h>

extern "C" {

// Forward declaration of the aom_codec_iface_t structure
struct aom_codec_iface {
    // Assuming there are some fields here, but they are not needed for this example
};

int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    // Ensure that the size is large enough to create a valid aom_codec_iface_t object
    if (size < sizeof(aom_codec_iface)) {
        return 0;
    }

    // Create a dummy aom_codec_iface_t object from the input data
    aom_codec_iface_t *iface = reinterpret_cast<aom_codec_iface_t *>(const_cast<uint8_t *>(data));

    // Call the function-under-test
    const char *name = aom_codec_iface_name(iface);

    // Prevent unused variable warning
    (void)name;

    return 0;
}

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
