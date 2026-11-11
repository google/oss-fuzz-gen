#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    GF_ISOFile *movie;
    u8 *moov_boxes;
    u32 moov_boxes_size;
    Bool udta_only;

    // Initialize variables
    movie = gf_isom_open("dummy.mp4", GF_ISOM_OPEN_READ, NULL);
    if (!movie) return 0;

    moov_boxes_size = size > 0 ? (u32)size : 1; // Ensure non-zero size
    moov_boxes = (u8 *)malloc(moov_boxes_size);
    if (!moov_boxes) {
        gf_isom_close(movie);
        return 0;
    }

    // Copy data to moov_boxes
    memcpy(moov_boxes, data, moov_boxes_size);

    // Set udta_only to a non-null value
    udta_only = size % 2 == 0 ? GF_TRUE : GF_FALSE;

    // Call the function-under-test
    gf_isom_load_extra_boxes(movie, moov_boxes, moov_boxes_size, udta_only);

    // Clean up
    free(moov_boxes);
    gf_isom_close(movie);

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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
