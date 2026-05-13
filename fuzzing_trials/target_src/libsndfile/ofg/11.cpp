#include <sndfile.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern "C" {
    const char * sf_get_string(SNDFILE *, int);
}

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    // Create a temporary file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzzing data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }
    close(fd);

    // Open the temporary file as a sound file
    SF_INFO sfinfo;
    SNDFILE *sndfile = sf_open(tmpl, SFM_READ, &sfinfo);
    if (sndfile == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Try different string types
    const int string_types[] = {
        SF_STR_TITLE,
        SF_STR_COPYRIGHT,
        SF_STR_SOFTWARE,
        SF_STR_ARTIST,
        SF_STR_COMMENT,
        SF_STR_DATE,
        SF_STR_ALBUM,
        SF_STR_LICENSE,
        SF_STR_TRACKNUMBER,
        SF_STR_GENRE
    };

    for (size_t i = 0; i < sizeof(string_types) / sizeof(string_types[0]); ++i) {
        const char *result = sf_get_string(sndfile, string_types[i]);
        if (result != NULL) {
            // Optionally, you can print the result for debugging purposes
            // printf("String Type %d: %s\n", string_types[i], result);
        }
    }

    // Clean up
    sf_close(sndfile);
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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
