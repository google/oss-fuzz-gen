#include <stddef.h>
#include <stdint.h>
#include <aom/aom_image.h>

extern "C" {
    size_t aom_img_num_metadata(const aom_image_t *);
}

extern "C" int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    aom_image_t img;
    
    // Initialize the aom_image_t with some non-NULL values
    img.fmt = AOM_IMG_FMT_I420; // Example format
    img.w = 640; // Example width
    img.h = 480; // Example height
    img.d_w = 640; // Display width
    img.d_h = 480; // Display height
    img.x_chroma_shift = 1;
    img.y_chroma_shift = 1;
    img.bps = 12;
    img.planes[0] = const_cast<uint8_t*>(data); // Use data as a plane
    img.stride[0] = (int)size; // Use size as stride
    img.img_data = const_cast<uint8_t*>(data); // Use data as image data
    img.img_data_owner = 0;
    img.self_allocd = 0;
    img.fb_priv = NULL;

    // Call the function-under-test
    size_t metadata_count = aom_img_num_metadata(&img);

    // Return 0 as required by the fuzzer
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

    LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
