#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include <aom/aom_image.h>
    #include <aom/aom_codec.h> // Include this for AOM_PLANE_COUNT

    void aom_img_flip(aom_image_t *);
}

extern "C" int LLVMFuzzerTestOneInput_65(const uint8_t *data, size_t size) {
    // Check if the size is sufficient for at least one plane
    if (size < 640 * 480 * 3 / 2) {
        return 0; // Not enough data to fill the image
    }

    // Initialize an aom_image_t structure
    aom_image_t img;
    img.fmt = AOM_IMG_FMT_I420; // Use a common format
    img.w = 640; // Set a default width
    img.h = 480; // Set a default height
    img.d_w = 640; // Displayed width
    img.d_h = 480; // Displayed height
    img.x_chroma_shift = 1;
    img.y_chroma_shift = 1;
    img.bit_depth = 8;

    // Allocate memory for image planes
    for (int i = 0; i < 3; ++i) { // AOM_PLANE_COUNT is typically 3 for I420 format
        img.stride[i] = img.w; // Set stride to width
    }

    // Allocate memory for the image data
    uint8_t *image_data = (uint8_t *)malloc(640 * 480 * 3 / 2);
    if (!image_data) {
        return 0; // Memory allocation failed
    }

    // Copy the input data to the allocated memory
    memcpy(image_data, data, 640 * 480 * 3 / 2);

    // Assign the planes
    img.planes[0] = image_data; // Y plane
    img.planes[1] = image_data + 640 * 480; // U plane
    img.planes[2] = image_data + 640 * 480 + 640 * 480 / 4; // V plane

    // Call the function under test
    aom_img_flip(&img);

    // Free the allocated memory
    free(image_data);

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

    LLVMFuzzerTestOneInput_65(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
