#include <string.h>
#include <sys/stat.h>
#include <cstdint>
#include <cstdlib>
#include "/src/aom/aom/aom_image.h"

extern "C" int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract all parameters
    if (size < sizeof(unsigned int) * 5) {
        return 0;
    }

    // Initialize parameters for aom_img_set_rect
    aom_image_t img;
    unsigned int x = static_cast<unsigned int>(data[0]);
    unsigned int y = static_cast<unsigned int>(data[1]);
    unsigned int w = static_cast<unsigned int>(data[2]);
    unsigned int h = static_cast<unsigned int>(data[3]);
    unsigned int stride = static_cast<unsigned int>(data[4]);

    // Call the function-under-test
    int result = aom_img_set_rect(&img, x, y, w, h, stride);

    // Return 0 to indicate the fuzzer should continue
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

    LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
