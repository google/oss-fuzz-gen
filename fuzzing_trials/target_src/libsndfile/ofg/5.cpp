#include <sndfile.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>  // Include this for close() and unlink()

extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    // Create a temporary file to use with libsndfile
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Initialize the SF_INFO structure
    SF_INFO sfinfo;
    memset(&sfinfo, 0, sizeof(SF_INFO));
    sfinfo.samplerate = 44100;  // Standard sample rate
    sfinfo.channels = 2;        // Stereo
    sfinfo.format = SF_FORMAT_WAV | SF_FORMAT_PCM_16;  // WAV file with PCM 16 format

    // Open the temporary file as a SNDFILE
    SNDFILE *sndfile = sf_open_fd(fd, SFM_WRITE, &sfinfo, 1);
    if (sndfile == NULL) {
        close(fd);
        return 0;
    }

    // Ensure the data size is appropriate for double array
    size_t num_doubles = size / sizeof(double);
    if (num_doubles == 0) {
        sf_close(sndfile);
        close(fd);
        return 0;
    }

    // Cast the input data to a double array
    const double *double_data = reinterpret_cast<const double *>(data);

    // Call the function-under-test
    sf_count_t frames_written = sf_writef_double(sndfile, double_data, static_cast<sf_count_t>(num_doubles));

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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
