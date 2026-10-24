#include <cstdint>
#include <cstdlib>
#include <aom/aom_image.h>

extern "C" int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to extract parameters
    if (size < sizeof(unsigned int) * 5) {
        return 0;
    }

    // Extract parameters from the input data
    unsigned int width = *(reinterpret_cast<const unsigned int*>(data));
    unsigned int height = *(reinterpret_cast<const unsigned int*>(data + sizeof(unsigned int)));
    unsigned int border = *(reinterpret_cast<const unsigned int*>(data + 2 * sizeof(unsigned int)));
    unsigned int stride_align = *(reinterpret_cast<const unsigned int*>(data + 3 * sizeof(unsigned int)));
    unsigned int size_align = *(reinterpret_cast<const unsigned int*>(data + 4 * sizeof(unsigned int)));

    // Set a valid image format
    aom_img_fmt_t img_fmt = AOM_IMG_FMT_I420;

    // Allocate an aom_image_t structure
    aom_image_t *img = nullptr;

    // Call the function-under-test
    aom_image_t *result = aom_img_alloc_with_border(img, img_fmt, width, height, border, stride_align, size_align);

    // Free the image if allocation was successful
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

    LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
