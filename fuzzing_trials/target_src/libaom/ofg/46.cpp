#include <cstddef>
#include <cstdint>
#include <aom/aom_image.h>

extern "C" {
    // Include the necessary AOM headers
    #include <aom/aom_image.h>
}

extern "C" int LLVMFuzzerTestOneInput_46(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0; // Not enough data to proceed
    }

    // Use input data to determine image parameters
    aom_image_t img;
    aom_image_t *img_ptr = &img;
    aom_img_fmt_t fmt = static_cast<aom_img_fmt_t>(data[0] % 4); // Limited to 4 formats
    unsigned int width = 640 + (data[1] % 640); // Vary width from 640 to 1279
    unsigned int height = 480 + (data[2] % 480); // Vary height from 480 to 959
    unsigned int align = 1 + (data[3] % 16); // Vary alignment from 1 to 16

    // Call the function-under-test
    aom_image_t *result = aom_img_alloc(img_ptr, fmt, width, height, align);

    // Free the allocated image if it was successfully allocated
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

    LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
