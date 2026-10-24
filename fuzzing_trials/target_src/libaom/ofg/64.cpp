extern "C" {
    #include <aom/aom_image.h>
    #include <aom/aom_encoder.h>
}

extern "C" int LLVMFuzzerTestOneInput_64(const uint8_t *data, size_t size) {
    // Ensure that the size is large enough to initialize aom_image_t
    if (size < sizeof(aom_image_t) + 640 * 480 * 3 / 2) { // I420 requires 1.5 bytes per pixel
        return 0;
    }

    // Create and initialize aom_image_t
    aom_image_t img;
    if (!aom_img_wrap(&img, AOM_IMG_FMT_I420, 640, 480, 1, const_cast<uint8_t*>(data))) {
        return 0;
    }

    // Call the function under test
    aom_img_flip(&img);

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

    LLVMFuzzerTestOneInput_64(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
