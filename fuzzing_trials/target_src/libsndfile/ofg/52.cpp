#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h> // Include for the close() function

extern "C" {
    #include <sndfile.h>
}

extern "C" int LLVMFuzzerTestOneInput_52(const uint8_t *data, size_t size) {
    // Temporary file setup
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    FILE *file = fdopen(fd, "wb");
    if (file == NULL) {
        close(fd);
        return 0;
    }

    // Write the data to the temporary file
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the temporary file with libsndfile
    SF_INFO sfinfo;
    SNDFILE *sndfile = sf_open(tmpl, SFM_READ, &sfinfo);

    if (sndfile != NULL) {
        // Call the function-under-test
        const char *error_str = sf_strerror(sndfile);

        // Use the error string in some way to avoid compiler optimizations
        if (error_str) {
            printf("Error: %s\n", error_str);
        }

        // Close the sound file
        sf_close(sndfile);
    }

    // Clean up the temporary file
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

    LLVMFuzzerTestOneInput_52(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
