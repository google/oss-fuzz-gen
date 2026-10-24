#include <sys/stat.h>
#include "sndfile.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
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

    // Close the file descriptor
    close(fd);

    // Open the temporary file with libsndfile
    SF_INFO sfinfo;
    SNDFILE *sndfile = sf_open(tmpl, SFM_READ, &sfinfo);
    if (sndfile == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Prepare buffer for reading samples
    sf_count_t frames_to_read = 1024; // Arbitrary number of frames to read
    double *buffer = (double *)malloc(frames_to_read * sfinfo.channels * sizeof(double));
    if (buffer == NULL) {
        sf_close(sndfile);
        unlink(tmpl);
        return 0;
    }

    // Call the function under test
    sf_count_t frames_read = sf_readf_double(sndfile, buffer, frames_to_read);

    // Clean up

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from sf_readf_double to sf_open_fd using the plateau pool
    SNDFILE* ret_sf_open_fd_ovdry = sf_open_fd((int )frames_read, SFM_WRITE, &sfinfo, (int )*buffer);
    if (ret_sf_open_fd_ovdry == NULL){
    	return 0;
    }
    // End mutation: Producer.SPLICE_MUTATOR
    
    free(buffer);
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

    LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
