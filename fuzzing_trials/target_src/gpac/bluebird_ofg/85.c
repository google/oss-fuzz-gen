#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "/src/gpac/include/gpac/isomedia.h"

int LLVMFuzzerTestOneInput_85(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = gf_isom_open("dummy.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (!movie) {
        return 0;
    }

    // Initialize parameters with non-zero values
    u32 trackNumber = 1;
    u32 StreamDescriptionIndex = 1;
    u32 cleanApertureWidthN = 1920;
    u32 cleanApertureWidthD = 1080;
    u32 cleanApertureHeightN = 1080;
    u32 cleanApertureHeightD = 1920;
    s32 horizOffN = 0;
    u32 horizOffD = 1;
    s32 vertOffN = 0;
    u32 vertOffD = 1;

    // Call the function-under-test
    gf_isom_set_clean_aperture(movie, trackNumber, StreamDescriptionIndex, 
                               cleanApertureWidthN, cleanApertureWidthD, 
                               cleanApertureHeightN, cleanApertureHeightD, 
                               horizOffN, horizOffD, vertOffN, vertOffD);

    // Close the movie file
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

    LLVMFuzzerTestOneInput_85(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
