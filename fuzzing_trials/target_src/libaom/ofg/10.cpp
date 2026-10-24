#include <cstdint>
#include <cstdlib>
#include <aom/aom_image.h>

extern "C" {
    #include <aom/aom_codec.h> // Include necessary headers for AOM_IMG_FMT_I420
    #include <aom/aom_integer.h> // Include for AOM_IMG_PLANES

    int aom_img_plane_width(const aom_image_t *img, int plane);

    // Define AOM_IMG_PLANES if not defined in the included headers
    #ifndef AOM_IMG_PLANES
    #define AOM_IMG_PLANES 3
    #endif
}

extern "C" int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to initialize the aom_image_t structure
    if (size < sizeof(aom_image_t)) {
        return 0;
    }

    // Initialize aom_image_t structure
    aom_image_t img;
    img.w = 640;  // Set a default width
    img.h = 480;  // Set a default height
    img.d_w = 640; // Display width
    img.d_h = 480; // Display height
    img.x_chroma_shift = 1;
    img.y_chroma_shift = 1;
    img.img_data = const_cast<uint8_t*>(data); // Use input data as image data
    img.img_data_owner = 0;
    img.self_allocd = 0;
    img.fmt = AOM_IMG_FMT_I420; // Set a default image format
    img.bps = 12; // Bits per sample

    // Initialize planes
    for (int i = 0; i < AOM_IMG_PLANES; ++i) {
        img.planes[i] = const_cast<uint8_t*>(data);
        img.stride[i] = 640; // Set a default stride
    }

    // Use the first byte of data to determine the plane index
    int plane = data[0] % AOM_IMG_PLANES;

    // Call the function-under-test
    int width = aom_img_plane_width(&img, plane);

    // Use the result to prevent optimization
    volatile int result = width;
    (void)result;

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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
