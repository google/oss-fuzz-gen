#include <cstdint>
#include <cstdlib>
#include <aom/aom_image.h>

extern "C" int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    aom_image_t *img = nullptr;
    aom_img_fmt_t fmt = AOM_IMG_FMT_I420; // Use a valid image format
    unsigned int width = 640;  // Default width
    unsigned int height = 480; // Default height
    unsigned int border = 32;  // Default border size
    unsigned int align = 16;   // Default alignment
    unsigned int stride_align = 16; // Default stride alignment

    // Ensure size is sufficient to extract parameters
    if (size >= sizeof(unsigned int) * 3) {
        width = static_cast<unsigned int>(data[0]);
        height = static_cast<unsigned int>(data[1]);
        border = static_cast<unsigned int>(data[2]);
    }

    // Call the function-under-test
    aom_image_t *result = aom_img_alloc_with_border(img, fmt, width, height, border, align, stride_align);

    // Clean up allocated resources if necessary
    if (result != nullptr) {
        aom_img_free(result);
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

    LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
