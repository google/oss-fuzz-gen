#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "/src/gpac/include/gpac/isomedia.h"

int LLVMFuzzerTestOneInput_82(const uint8_t *data, size_t size) {
    GF_ISOFile *movie;
    u32 trackNumber;
    u32 StreamDescriptionIndex;
    u32 Width;
    u32 Height;

    // Ensure the size is large enough to extract all required parameters
    if (size < sizeof(trackNumber) + sizeof(StreamDescriptionIndex) + sizeof(Width) + sizeof(Height)) {
        return 0;
    }

    // Initialize parameters from the input data
    trackNumber = *((u32 *)data);
    data += sizeof(u32);
    size -= sizeof(u32);

    StreamDescriptionIndex = *((u32 *)data);
    data += sizeof(u32);
    size -= sizeof(u32);

    Width = *((u32 *)data);
    data += sizeof(u32);
    size -= sizeof(u32);

    Height = *((u32 *)data);
    data += sizeof(u32);
    size -= sizeof(u32);

    // Initialize a GF_ISOFile object
    movie = gf_isom_open("dummy.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (movie == NULL) {
        return 0;
    }

    // Call the function-under-test
    gf_isom_set_visual_info(movie, trackNumber, StreamDescriptionIndex, Width, Height);

    // Close and clean up the movie object
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
