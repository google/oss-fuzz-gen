#include <cstdint>
#include <cstdlib>
#include <aom/aom_image.h>

extern "C" int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < sizeof(unsigned int) * 3 + sizeof(aom_img_fmt_t)) {
        return 0;
    }

    // Extract parameters from the data
    unsigned int width = *(reinterpret_cast<const unsigned int*>(data));
    unsigned int height = *(reinterpret_cast<const unsigned int*>(data + sizeof(unsigned int)));
    unsigned int stride = *(reinterpret_cast<const unsigned int*>(data + 2 * sizeof(unsigned int)));
    aom_img_fmt_t fmt = *(reinterpret_cast<const aom_img_fmt_t*>(data + 3 * sizeof(unsigned int)));

    // Ensure width, height, and stride are non-zero
    width = width == 0 ? 1 : width;
    height = height == 0 ? 1 : height;
    stride = stride == 0 ? 1 : stride;

    // Allocate memory for the image data
    unsigned char *img_data = new unsigned char[width * height];
    
    // Ensure img_data is not null
    if (!img_data) {
        return 0;
    }

    // Call the function-under-test
    aom_image_t *img = aom_img_wrap(nullptr, fmt, width, height, stride, img_data);

    // Clean up
    if (img) {
        aom_img_free(img);
    }
    delete[] img_data;

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

    LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
