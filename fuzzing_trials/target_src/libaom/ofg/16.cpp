extern "C" {
#include <stdint.h>
#include <stdlib.h>
#include <aom/aom_image.h>

// Function signature from the task
int aom_img_plane_height(const aom_image_t *img, int plane);
}

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    // Ensure there's enough data to initialize the aom_image_t structure
    if (size < sizeof(aom_image_t)) {
        return 0;
    }

    // Initialize aom_image_t structure
    aom_image_t img;
    img.fmt = AOM_IMG_FMT_I420; // Example format
    img.w = 640; // Example width
    img.h = 480; // Example height
    img.d_w = 640; // Display width
    img.d_h = 480; // Display height
    img.x_chroma_shift = 1;
    img.y_chroma_shift = 1;
    img.bps = 12;
    img.planes[0] = (uint8_t *)data; // Assigning data to the first plane
    img.stride[0] = 640; // Example stride

    // Initialize plane index
    int plane = 0; // Example plane index

    // Call the function-under-test
    int result = aom_img_plane_height(&img, plane);

    // Use the result to prevent compiler optimizations
    volatile int prevent_optimization = result;
    (void)prevent_optimization;

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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
