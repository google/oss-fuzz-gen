#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h>

// Define the fuzzer entry point without using extern "C"
int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract all parameters
    if (size < sizeof(uint32_t) * 4 + sizeof(uint8_t) + sizeof(GF_AudioSampleEntryImportMode)) {
        return 0;
    }

    // Initialize parameters
    GF_ISOFile *movie = gf_isom_open("dummy.mp4", GF_ISOM_OPEN_WRITE, NULL); // Create a dummy ISO file
    if (!movie) {
        return 0;
    }

    uint32_t trackNumber = *(uint32_t *)(data);
    uint32_t StreamDescriptionIndex = *(uint32_t *)(data + sizeof(uint32_t));
    uint32_t sampleRate = *(uint32_t *)(data + 2 * sizeof(uint32_t));
    uint32_t nbChannels = *(uint32_t *)(data + 3 * sizeof(uint32_t));
    uint8_t bitsPerSample = *(uint8_t *)(data + 4 * sizeof(uint32_t));
    GF_AudioSampleEntryImportMode asemode = *(GF_AudioSampleEntryImportMode *)(data + 4 * sizeof(uint32_t) + sizeof(uint8_t));

    // Call the function under test
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

    LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
