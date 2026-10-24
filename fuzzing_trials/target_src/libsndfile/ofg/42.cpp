extern "C" {
    #include <sndfile.h>
    #include <stdint.h>
    #include <stdlib.h>
    #include <stdio.h>
    #include <unistd.h> // Include for close() and unlink()
}

extern "C" int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    // Initialize variables before goto
    SNDFILE *sndfile = NULL;
    SF_INFO sfinfo;
    int *int_buffer = NULL;
    sf_count_t count_written = 0;
    FILE *temp_file = NULL;

    // Create a temporary file to use with SNDFILE
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    temp_file = fdopen(fd, "w+b");
    if (!temp_file) {
        close(fd);
        return 0;
    }

    // Initialize SF_INFO structure
    sfinfo.format = SF_FORMAT_WAV | SF_FORMAT_PCM_16;
    sfinfo.channels = 1;
    sfinfo.samplerate = 44100;

    // Open the temporary file with sf_open_fd
    sndfile = sf_open_fd(fd, SFM_WRITE, &sfinfo, 0);
    if (!sndfile) {
        fclose(temp_file);
        return 0;
    }

    // Allocate memory for int buffer
    int_buffer = (int *)malloc(size * sizeof(int));
    if (!int_buffer) {
        goto cleanup;
    }

    // Copy data into int buffer
    for (size_t i = 0; i < size; ++i) {
        int_buffer[i] = (int)data[i];
    }

    // Call the function-under-test
    count_written = sf_write_int(sndfile, int_buffer, (sf_count_t)size);

cleanup:
    if (int_buffer) {
        free(int_buffer);
    }
    if (sndfile) {
        sf_close(sndfile);
    }
    if (temp_file) {
        fclose(temp_file);
        unlink(tmpl);
    }

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

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
