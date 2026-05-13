#include <sndfile.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>  // Include this header for the close() function

extern "C" int LLVMFuzzerTestOneInput_65(const uint8_t *data, size_t size) {
    SNDFILE *sndfile;
    SF_INFO sfinfo;
    short *buffer;
    sf_count_t frames_to_write;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);

    // Initialize SF_INFO structure
    memset(&sfinfo, 0, sizeof(SF_INFO));
    sfinfo.samplerate = 44100;
    sfinfo.channels = 2;
    sfinfo.format = SF_FORMAT_WAV | SF_FORMAT_PCM_16;

    // Open a temporary file for writing
    sndfile = sf_open(tmpl, SFM_WRITE, &sfinfo);
    if (sndfile == NULL) {
        close(fd);
        return 0;
    }

    // Calculate the number of frames to write
    frames_to_write = size / sizeof(short);
    if (frames_to_write == 0) {
        sf_close(sndfile);
        close(fd);
        return 0;
    }

    // Allocate buffer for audio data
    buffer = (short *)malloc(frames_to_write * sizeof(short));
    if (buffer == NULL) {
        sf_close(sndfile);
        close(fd);
        return 0;
    }

    // Copy fuzz data into the buffer
    memcpy(buffer, data, frames_to_write * sizeof(short));

    // Call the function-under-test
    sf_write_short(sndfile, buffer, frames_to_write);

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

    LLVMFuzzerTestOneInput_65(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
