#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_82(const uint8_t *data, size_t size) {
    // Adjust the size check to not include sizeof(GF_ISOFile) since it's an incomplete type
    if (size < 3 * sizeof(uint32_t) + 3 * sizeof(bool)) {
        // Not enough data to extract all parameters
        return 0;
    }

    // Initialize the GF_ISOFile structure
    GF_ISOFile *movie = gf_isom_open("temp.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (!movie) {
        return 0;
    }

    // Extract parameters from the input data
    uint32_t trackNumber = *((uint32_t *)(data));
    uint32_t StreamDescriptionIndex = *((uint32_t *)(data + sizeof(uint32_t)));
    bool remove = *((bool *)(data + 2 * sizeof(uint32_t)));
    bool all_ref_pics_intra = *((bool *)(data + 2 * sizeof(uint32_t) + sizeof(bool)));
    bool intra_pred_used = *((bool *)(data + 2 * sizeof(uint32_t) + 2 * sizeof(bool)));
    uint32_t max_ref_per_pic = *((uint32_t *)(data + 2 * sizeof(uint32_t) + 3 * sizeof(bool)));

    // Call the function-under-test
    gf_isom_set_image_sequence_coding_constraints(movie, trackNumber, StreamDescriptionIndex, remove, all_ref_pics_intra, intra_pred_used, max_ref_per_pic);

    // Clean up
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

    LLVMFuzzerTestOneInput_82(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
