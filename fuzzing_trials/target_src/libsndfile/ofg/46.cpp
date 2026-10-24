#include <sndfile.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h> // Include this for the 'close' function

extern "C" {
    // Wrap C library functions to ensure correct linkage
    #include <sndfile.h>
}

extern "C" int LLVMFuzzerTestOneInput_46(const uint8_t *data, size_t size) {
    // Ensure there is enough data to proceed
    if (size < sizeof(double)) {
        return 0;
    }

    // Create a temporary file to use with SNDFILE
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Define the format for the sound file
    SF_INFO sfinfo;
    memset(&sfinfo, 0, sizeof(SF_INFO));
    sfinfo.channels = 1;
    sfinfo.samplerate = 44100;
    sfinfo.format = SF_FORMAT_WAV | SF_FORMAT_PCM_16;

    // Open the sound file for writing
    SNDFILE *sndfile = sf_open_fd(fd, SFM_WRITE, &sfinfo, 0);
    if (!sndfile) {
        close(fd);
        return 0;
    }

    // Prepare the buffer of doubles to write
    size_t num_doubles = size / sizeof(double);
    const double *double_data = reinterpret_cast<const double *>(data);

    // Call the function under test
    sf_count_t written_frames = sf_write_double(sndfile, double_data, num_doubles);

    // Clean up
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

    LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
