extern "C" {
    #include <sndfile.h>
    #include <stdint.h>
    #include <stdlib.h>
    #include <stdio.h>
    #include <unistd.h> // Include for close() and unlink()
}

extern "C" int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size) {
    // Ensure that the size is non-zero for valid file operations
    if (size == 0) return 0;

    // Create a temporary file to use with the SNDFILE* handle
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) return 0;

    // Use the file descriptor to create a FILE* stream
    FILE *file = fdopen(fd, "wb+");
    if (!file) {
        close(fd);
        return 0;
    }

    // Initialize SF_INFO structure
    SF_INFO sfinfo;
    sfinfo.frames = 0;
    sfinfo.samplerate = 44100; // Standard sample rate
    sfinfo.channels = 2; // Stereo
    sfinfo.format = SF_FORMAT_WAV | SF_FORMAT_PCM_16; // Common format

    // Open the file as a SNDFILE* handle
    SNDFILE *sndfile = sf_open_fd(fd, SFM_WRITE, &sfinfo, SF_FALSE);
    if (!sndfile) {
        fclose(file);
        return 0;
    }

    // Call the function-under-test
    sf_count_t count = sf_write_raw(sndfile, data, (sf_count_t)size);

    // Clean up
    sf_close(sndfile);
    fclose(file);
    unlink(tmpl); // Remove the temporary file

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

    LLVMFuzzerTestOneInput_58(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
