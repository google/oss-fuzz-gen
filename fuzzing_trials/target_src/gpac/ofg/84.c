#include <stdint.h>
#include <stddef.h>
#include <gpac/isomedia.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_84(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = gf_isom_open((const char*)data, GF_ISOM_OPEN_READ, NULL);
    if (movie == NULL) {
        return 0;
    }

    u32 trackNumber = 1; // Assuming at least one track exists, use a valid track number

    gf_isom_add_track_to_root_od(movie, trackNumber);

    gf_isom_close(movie);
    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_84(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
