#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_34(const uint8_t *data, size_t size) {
    // Ensure there's enough data for all parameters
    if (size < sizeof(u32) * 4 + sizeof(u8) + sizeof(GF_AudioSampleEntryImportMode)) {
        return 0;
    }

    // Initialize parameters from the input data
    u32 trackNumber = *((u32 *)data);
    u32 StreamDescriptionIndex = *((u32 *)(data + sizeof(u32)));
    u32 sampleRate = *((u32 *)(data + sizeof(u32) * 2));
    u32 nbChannels = *((u32 *)(data + sizeof(u32) * 3));
    u8 bitsPerSample = *(data + sizeof(u32) * 4);
    GF_AudioSampleEntryImportMode asemode = (GF_AudioSampleEntryImportMode)*(data + sizeof(u32) * 4 + sizeof(u8));

    // Create a dummy GF_ISOFile object
    GF_ISOFile *movie = gf_isom_open("dummy.mp4", GF_ISOM_OPEN_WRITE, NULL);

    if (movie == NULL) {
        return 0;
    }

    // Call the function-under-test
    gf_isom_set_audio_info(movie, trackNumber, StreamDescriptionIndex, sampleRate, nbChannels, bitsPerSample, asemode);

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

    LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
