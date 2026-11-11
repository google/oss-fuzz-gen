#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "/src/gpac/include/gpac/isomedia.h"

int LLVMFuzzerTestOneInput_86(const uint8_t *data, size_t size) {
    // Ensure the input size is large enough to safely access the data array
    if (size < 4) {
        return 0;
    }

    GF_ISOFile *movie = gf_isom_open("dummy.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (!movie) {
        return 0;
    }

    u32 trackNumber = 1;
    u32 StreamDescriptionIndex = 1;
    Bool remove = (Bool)(data[0] % 2);
    Bool all_ref_pics_intra = (Bool)(data[1] % 2);
    Bool intra_pred_used = (Bool)(data[2] % 2);
    u32 max_ref_per_pic = (u32)data[3];

    gf_isom_set_image_sequence_coding_constraints(movie, trackNumber, StreamDescriptionIndex, remove, all_ref_pics_intra, intra_pred_used, max_ref_per_pic);

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

    LLVMFuzzerTestOneInput_86(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
