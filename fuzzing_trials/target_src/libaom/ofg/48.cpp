#include <cstdint>
#include <cstdlib>
#include <aom/aom_image.h>

extern "C" int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size) {
    if (size < sizeof(unsigned int) * 5 + sizeof(aom_image_t)) {
        return 0;
    }

    // Initialize the aom_image_t structure
    aom_image_t img;
    img.img_data = const_cast<uint8_t*>(data); // Assuming data is non-NULL and valid
    img.d_w = 640; // Example width
    img.d_h = 480; // Example height
    img.x_chroma_shift = 1;
    img.y_chroma_shift = 1;
    img.img_data_owner = 1;
    img.fmt = AOM_IMG_FMT_I420; // Example format

    // Extract unsigned int values from the input data
    unsigned int x = *(reinterpret_cast<const unsigned int*>(data));
    unsigned int y = *(reinterpret_cast<const unsigned int*>(data + sizeof(unsigned int)));
    unsigned int w = *(reinterpret_cast<const unsigned int*>(data + 2 * sizeof(unsigned int)));
    unsigned int h = *(reinterpret_cast<const unsigned int*>(data + 3 * sizeof(unsigned int)));
    unsigned int stride = *(reinterpret_cast<const unsigned int*>(data + 4 * sizeof(unsigned int)));

    // Call the function-under-test
    aom_img_set_rect(&img, x, y, w, h, stride);

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

    LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
