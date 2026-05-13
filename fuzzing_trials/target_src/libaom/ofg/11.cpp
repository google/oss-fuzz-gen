#include <stdint.h>
#include <stddef.h>
#include <aom/aom_image.h>

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    // Declare and initialize aom_image_t structure
    aom_image_t img;
    
    // Initialize the image with some default values
    img.fmt = AOM_IMG_FMT_I420; // Using a common format
    img.w = 640;                // Width
    img.h = 480;                // Height
    img.d_w = 640;              // Displayed width
    img.d_h = 480;              // Displayed height
    img.x_chroma_shift = 1;     // Chroma shift values
    img.y_chroma_shift = 1;
    img.bps = 12;               // Bits per sample
    img.planes[0] = (unsigned char *)data; // Assign data to the first plane
    img.stride[0] = (int)size;  // Assign size to the stride for simplicity

    // Call the function-under-test
    aom_img_free(&img);

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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
