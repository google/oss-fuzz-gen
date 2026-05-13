#include <cstdint>
#include <cstdlib>
#include <aom/aom_image.h>

extern "C" int LLVMFuzzerTestOneInput_51(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to initialize aom_image_t
    if (size < sizeof(aom_image_t)) {
        return 0;
    }

    // Allocate and initialize aom_image_t
    aom_image_t img;
    // Use the data to initialize the image structure
    // This is a simplistic initialization for fuzzing purposes
    img.fmt = static_cast<aom_img_fmt_t>(data[0] % 5); // Assuming 5 different formats
    img.w = static_cast<uint32_t>(data[1]);
    img.h = static_cast<uint32_t>(data[2]);
    img.d_w = static_cast<uint32_t>(data[3]);
    img.d_h = static_cast<uint32_t>(data[4]);
    img.x_chroma_shift = static_cast<uint8_t>(data[5] % 3); // Assuming max shift of 2
    img.y_chroma_shift = static_cast<uint8_t>(data[6] % 3); // Assuming max shift of 2
    img.bps = static_cast<uint8_t>(data[7]);
    img.bit_depth = static_cast<uint8_t>(data[8]);
    img.planes[0] = const_cast<uint8_t*>(&data[9]); // Point to some data within bounds
    img.stride[0] = static_cast<int>(data[10]);

    // Call the function-under-test
    size_t num_metadata = aom_img_num_metadata(&img);

    // Use the result to prevent optimization out
    volatile size_t result = num_metadata;
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

    LLVMFuzzerTestOneInput_51(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
