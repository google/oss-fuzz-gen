#include <string.h>
#include <sys/stat.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include "/src/aom/aom/aom_image.h"
#include "/src/aom/aom/aom_codec.h"

extern "C" {
    const aom_metadata_t * aom_img_get_metadata(const aom_image_t *, size_t);
}

extern "C" int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    if (size < sizeof(aom_image_t) + 640 * 480) {
        return 0; // Not enough data to form a valid aom_image_t and fill the image plane
    }

    // Allocate and initialize aom_image_t
    aom_image_t img;
    memset(&img, 0, sizeof(aom_image_t));

    // Fill the aom_image_t with data, ensuring no NULL pointers
    img.fmt = AOM_IMG_FMT_I420; // Example format
    img.w = 640; // Example width
    img.h = 480; // Example height
    img.d_w = 640; // Display width
    img.d_h = 480; // Display height
    img.x_chroma_shift = 1;
    img.y_chroma_shift = 1;
    img.bps = 8;

    // Use input data for plane, ensuring it's not null
    img.planes[0] = const_cast<uint8_t*>(data + sizeof(aom_image_t)); 
    img.stride[0] = 640; // Example stride

    // Call the function-under-test
    const aom_metadata_t *metadata = aom_img_get_metadata(&img, size - sizeof(aom_image_t));

    // Normally, you would check or use the metadata here, but since this is a fuzz test, we just return
    (void)metadata; // Prevent unused variable warning

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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
