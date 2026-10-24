#include <sndfile.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // Added for close() and unlink()

extern "C" int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    // Define the temporary file for writing
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Initialize SF_INFO structure
    SF_INFO sfinfo;
    memset(&sfinfo, 0, sizeof(SF_INFO));
    sfinfo.samplerate = 44100;
    sfinfo.channels = 2;
    sfinfo.format = SF_FORMAT_WAV | SF_FORMAT_PCM_16;

    // Open the temporary file as a sound file
    SNDFILE *sndfile = sf_open_fd(fd, SFM_WRITE, &sfinfo, 1);
    if (sndfile == NULL) {
        close(fd);
        return 0;
    }

    // Prepare float buffer from the input data
    sf_count_t num_samples = size / sizeof(float);
    float *float_buffer = (float *)malloc(num_samples * sizeof(float));
    if (float_buffer == NULL) {
        sf_close(sndfile);
        close(fd);
        return 0;
    }

    // Copy data into float buffer
    memcpy(float_buffer, data, num_samples * sizeof(float));

    // Call the function-under-test
    sf_write_float(sndfile, float_buffer, num_samples);

    // Clean up
    free(float_buffer);
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

    LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
