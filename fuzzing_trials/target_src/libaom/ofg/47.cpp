#include <stdint.h>
#include <stddef.h>
#include <aom/aom_image.h>

extern "C" int LLVMFuzzerTestOneInput_47(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    aom_image_t img;
    aom_image_t *img_ptr = &img;
    aom_img_fmt_t fmt = AOM_IMG_FMT_I420; // Choose a valid image format
    unsigned int d_w = 640; // Default width
    unsigned int d_h = 480; // Default height
    unsigned int align = 1; // Default alignment

    // Call the function-under-test
    aom_image_t *result = aom_img_alloc(img_ptr, fmt, d_w, d_h, align);

    // Free the allocated image if successful
    if (result != NULL) {
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

    LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
