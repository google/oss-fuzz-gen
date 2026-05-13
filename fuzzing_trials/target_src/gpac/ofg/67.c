#include <stdint.h>
#include <stddef.h>
#include <string.h> // For memcpy
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_67(const uint8_t *data, size_t size) {
    // Ensure size is large enough to extract necessary values
    if (size < sizeof(u32) * 2 + sizeof(GF_AudioChannelLayout)) {
        return 0;
    }

    // Initialize the parameters for gf_isom_set_audio_layout
    GF_ISOFile *movie = gf_isom_open("dummy.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (!movie) {
        return 0;
    }

    // Extract trackNumber and sampleDescriptionIndex from the data
    u32 trackNumber = *(const u32 *)data;
    u32 sampleDescriptionIndex = *(const u32 *)(data + sizeof(u32));

    // Extract GF_AudioChannelLayout from the data
    GF_AudioChannelLayout layout;
    memcpy(&layout, data + sizeof(u32) * 2, sizeof(GF_AudioChannelLayout));

    // Call the function-under-test
    gf_isom_set_audio_layout(movie, trackNumber, sampleDescriptionIndex, &layout);

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

    LLVMFuzzerTestOneInput_67(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
