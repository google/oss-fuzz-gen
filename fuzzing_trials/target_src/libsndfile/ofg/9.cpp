#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>  // Include for the close function

extern "C" {
    #include <sndfile.h>
}

extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
    SNDFILE *sndfile;
    SF_INFO sfinfo;
    sf_count_t frames_written;
    short *buffer;
    sf_count_t frame_count;

    // Initialize SF_INFO structure
    memset(&sfinfo, 0, sizeof(SF_INFO));
    sfinfo.channels = 1; // Mono audio
    sfinfo.samplerate = 44100; // Standard sample rate
    sfinfo.format = SF_FORMAT_WAV | SF_FORMAT_PCM_16; // WAV format with 16-bit PCM

    // Create a temporary file to write the audio data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Open the temporary file as a sound file
    sndfile = sf_open_fd(fd, SFM_WRITE, &sfinfo, 0);
    if (sndfile == NULL) {
        close(fd);
        return 0;
    }

    // Ensure the data size is a multiple of the size of short
    if (size % sizeof(short) != 0) {
        size -= size % sizeof(short);
    }

    // Calculate frame count
    frame_count = size / sizeof(short);

    // Allocate buffer for audio data
    buffer = (short *)malloc(size);
    if (buffer == NULL) {
        sf_close(sndfile);
        close(fd);
        return 0;
    }

    // Copy data to buffer
    memcpy(buffer, data, size);

    // Call the function-under-test
    frames_written = sf_writef_short(sndfile, buffer, frame_count);

    // Clean up
    free(buffer);
    sf_close(sndfile);
    close(fd);
    remove(tmpl);

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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
