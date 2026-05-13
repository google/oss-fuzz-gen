#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // Include this for the 'close' function

extern "C" {
    #include "sndfile.h"
    // Include the necessary C headers and function declarations
    int sf_set_string(SNDFILE *, int, const char *);
}

extern "C" int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    SNDFILE *sndfile = NULL;
    SF_INFO sfinfo;
    int string_type;
    char *str = NULL;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd;

    // Ensure size is sufficient for string_type and at least one character for the string
    if (size < sizeof(int) + 1) {
        return 0;
    }

    // Create a temporary file
    fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Initialize SF_INFO structure
    memset(&sfinfo, 0, sizeof(SF_INFO));
    sfinfo.samplerate = 44100;
    sfinfo.channels = 2;
    sfinfo.format = SF_FORMAT_WAV | SF_FORMAT_PCM_16;

    // Open the temporary file as a sound file
    sndfile = sf_open(tmpl, SFM_WRITE, &sfinfo);
    if (sndfile == NULL) {
        close(fd);
        remove(tmpl);
        return 0;
    }

    // Extract string_type from data
    memcpy(&string_type, data, sizeof(int));

    // Allocate and copy the string from data
    str = (char *)malloc(size - sizeof(int) + 1);
    if (str == NULL) {
        sf_close(sndfile);
        close(fd);
        remove(tmpl);
        return 0;
    }
    memcpy(str, data + sizeof(int), size - sizeof(int));
    str[size - sizeof(int)] = '\0'; // Null-terminate the string

    // Call the function-under-test
    sf_set_string(sndfile, string_type, str);

    // Clean up
    free(str);
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

    LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
