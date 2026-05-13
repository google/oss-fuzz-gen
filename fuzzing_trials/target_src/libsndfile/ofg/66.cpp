#include <stdint.h>
#include <stdlib.h>
#include <sndfile.h>
#include <unistd.h> // Include this header for the 'close' function

extern "C" {
    // Wrap C functions and headers in extern "C" to ensure proper linkage
    #include <sndfile.h>
}

extern "C" int LLVMFuzzerTestOneInput_66(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    SNDFILE *sndfile = NULL;
    SF_INFO sfinfo;
    short *buffer = NULL;
    sf_count_t frames = 0;
    sf_count_t result;

    // Initialize SF_INFO structure
    sfinfo.frames = 0;
    sfinfo.samplerate = 44100;
    sfinfo.channels = 2;
    sfinfo.format = SF_FORMAT_WAV | SF_FORMAT_PCM_16;

    // Create a temporary file to open with sndfile
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Open the temporary file with sndfile
    sndfile = sf_open_fd(fd, SFM_WRITE, &sfinfo, 0);
    if (sndfile == NULL) {
        close(fd);
        return 0;
    }

    // Allocate buffer for short data
    buffer = (short *)malloc(size * sizeof(short));
    if (buffer == NULL) {
        sf_close(sndfile);
        close(fd);
        return 0;
    }

    // Copy data into buffer
    for (size_t i = 0; i < size; ++i) {
        buffer[i] = (short)data[i];
    }

    // Calculate number of frames
    frames = size / sizeof(short);

    // Call the function under test
    result = sf_write_short(sndfile, buffer, frames);

    // Clean up
    free(buffer);
    sf_close(sndfile);
    close(fd);

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

    LLVMFuzzerTestOneInput_66(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
