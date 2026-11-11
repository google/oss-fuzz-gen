#include <sndfile.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size) {
    // Define variables
    SNDFILE *sndfile;
    SF_INFO sfinfo;
    float *float_data;
    sf_count_t frames;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd;

    // Initialize SF_INFO structure
    sfinfo.format = SF_FORMAT_WAV | SF_FORMAT_PCM_16;
    sfinfo.channels = 1;
    sfinfo.samplerate = 44100;

    // Create a temporary file
    fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Open the temporary file as a sound file
    sndfile = sf_open(tmpl, SFM_WRITE, &sfinfo);
    if (sndfile == NULL) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Allocate memory for float data
    frames = size / sizeof(float);
    float_data = (float *)malloc(frames * sizeof(float));
    if (float_data == NULL) {
        sf_close(sndfile);
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Copy data into float array
    for (sf_count_t i = 0; i < frames; ++i) {
        float_data[i] = ((float *)data)[i];
    }

    // Call the function-under-test
    sf_writef_float(sndfile, float_data, frames);

    // Clean up
    free(float_data);
    sf_close(sndfile);
    close(fd);
    unlink(tmpl);

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

    LLVMFuzzerTestOneInput_56(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
