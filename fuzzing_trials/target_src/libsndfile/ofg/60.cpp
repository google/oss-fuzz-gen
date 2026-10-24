#include <sndfile.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h> // Include this header for 'close' and 'write' functions

extern "C" int LLVMFuzzerTestOneInput_60(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0;
    }

    // Create a temporary file to simulate a sound file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return 0;
    }

    // Close the file descriptor so that sf_open can open it
    close(fd);

    // Open the temporary file as a sound file
    SF_INFO sfinfo;
    SNDFILE *sndfile = sf_open(tmpl, SFM_READ, &sfinfo);
    if (sndfile == NULL) {
        return 0;
    }

    // Prepare parameters for sf_command
    int command = SF_STR_TITLE; // Example command, can be varied
    char buffer[256];
    int buffer_size = sizeof(buffer);

    // Call the function-under-test
    sf_command(sndfile, command, buffer, buffer_size);

    // Clean up
    sf_close(sndfile);
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

    LLVMFuzzerTestOneInput_60(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
