#include <cstdint>
#include <cstdlib>
#include <sndfile.h>
#include <unistd.h> // Include for close and unlink

extern "C" {
    #include <sndfile.h>
}

extern "C" int LLVMFuzzerTestOneInput_47(const uint8_t *data, size_t size) {
    // Ensure there's enough data to proceed
    if (size < sizeof(double)) {
        return 0;
    }

    // Create a temporary file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Define and initialize SF_INFO structure
    SF_INFO sfinfo;
    sfinfo.frames = 0;
    sfinfo.samplerate = 44100; // Common sample rate
    sfinfo.channels = 1;       // Mono
    sfinfo.format = SF_FORMAT_WAV | SF_FORMAT_PCM_16;

    // Open the sound file
    SNDFILE *sndfile = sf_open_fd(fd, SFM_WRITE, &sfinfo, 0);
    if (sndfile == NULL) {
        close(fd);
        return 0;
    }

    // Prepare the double buffer from the input data
    const double *double_data = reinterpret_cast<const double *>(data);
    sf_count_t count = size / sizeof(double);

    // Call the function-under-test
    sf_write_double(sndfile, double_data, count);

    // Clean up
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

    LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
