#include <sndfile.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_72(const uint8_t *data, size_t size) {
    // Create a temporary file to store the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // If the file creation fails, exit the fuzzer
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpl);
        return 0; // If writing fails, clean up and exit
    }

    // Close the file descriptor as it will be opened by sf_open
    close(fd);

    // Initialize SF_INFO structure
    SF_INFO sfinfo;
    memset(&sfinfo, 0, sizeof(SF_INFO));

    // Call the function-under-test
    SNDFILE *sndfile = sf_open(tmpl, SFM_READ, &sfinfo);

    // Clean up
    if (sndfile != NULL) {
        sf_close(sndfile);
    }
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

    LLVMFuzzerTestOneInput_72(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
