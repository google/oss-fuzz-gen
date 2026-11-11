#include <string.h>
#include <sys/stat.h>
#include <cstdint>
#include <cstdlib>
#include "/src/aom/aom/aom_image.h"

extern "C" {
    // Include the header for the function-under-test
    #include "/src/aom/aom/aom_image.h"
}

// Define the function-under-test
extern "C" int aom_img_plane_height(const aom_image_t *img, int plane);

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    // Initialize the aom_image_t structure
    aom_image_t img;
    img.d_w = 640; // Set a default width
    img.d_h = 480; // Set a default height
    img.fmt = AOM_IMG_FMT_I420; // Set a default format
    img.bit_depth = 8; // Set a default bit depth

    // Ensure the data size is sufficient for testing
    if (size < sizeof(aom_image_t)) {
        return 0;
    }

    // Use the first byte of data to determine the plane index
    int plane = static_cast<int>(data[0] % 3); // Assuming 3 planes: Y, U, V

    // Call the function-under-test
    int height = aom_img_plane_height(&img, plane);

    // Use the result in some way to avoid compiler optimizations removing the call
    volatile int result = height;
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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
