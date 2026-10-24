#include <cstdint>
#include <cstdlib>
#include <aom/aom_image.h>

extern "C" int LLVMFuzzerTestOneInput_34(const uint8_t *data, size_t size) {
    if (size < 5) {
        return 0; // Ensure there's enough data for the parameters
    }

    // Initialize parameters for aom_img_wrap
    aom_image_t img; // Uninitialized image structure
    aom_img_fmt_t fmt = static_cast<aom_img_fmt_t>(data[0] % 10); // Enum value, assuming 10 possible formats
    unsigned int d_w = data[1] + 1; // Width, ensuring it's non-zero
    unsigned int d_h = data[2] + 1; // Height, ensuring it's non-zero
    unsigned int stride_align = data[3] + 1; // Stride alignment, ensuring it's non-zero
    unsigned char *img_data = const_cast<unsigned char*>(data + 4); // Image data starts from the 5th byte

    // Call the function-under-test
    aom_image_t *result = aom_img_wrap(&img, fmt, d_w, d_h, stride_align, img_data);

    // Optionally, you can perform additional checks or operations on the result
    // For now, just ensure the result is used to avoid compiler optimizations
    if (result != nullptr) {
        // Perform some operations if needed
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

    LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
