#include <sndfile.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // Include this for close and unlink
#include <fcntl.h>  // Include this for mkstemp

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    // Ensure there is enough data to create a valid short array
    if (size < sizeof(short)) {
        return 0;
    }

    // Create a temporary file to use with libsndfile
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Create an SF_INFO structure with default values
    SF_INFO sfinfo;
    memset(&sfinfo, 0, sizeof(SF_INFO));
    sfinfo.channels = 1;
    sfinfo.samplerate = 44100;
    sfinfo.format = SF_FORMAT_WAV | SF_FORMAT_PCM_16;

    // Open the temporary file as a sound file
    SNDFILE *sndfile = sf_open_fd(fd, SFM_WRITE, &sfinfo, 1);
    if (sndfile == NULL) {
        close(fd);
        return 0;
    }

    // Cast the data to short array
    const short *short_data = reinterpret_cast<const short *>(data);
    sf_count_t frames = static_cast<sf_count_t>(size / sizeof(short));

    // Call the function-under-test
    sf_writef_short(sndfile, short_data, frames);

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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
