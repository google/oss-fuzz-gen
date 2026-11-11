#include <sys/stat.h>
#include "sndfile.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sf_readf_double to sf_command
    // Ensure dataflow is valid (i.e., non-null)
    if (!sndfile) {
    	return 0;
    }
    sf_write_sync(sndfile);
    // Ensure dataflow is valid (i.e., non-null)
    if (!sndfile) {
    	return 0;
    }
    const char* ret_sf_strerror_ojmvi = sf_strerror(sndfile);
    if (ret_sf_strerror_ojmvi == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!sndfile) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!sndfile) {
    	return 0;
    }
    int ret_sf_command_ptosy = sf_command(sndfile, (int )*buffer, (void *)sndfile, 1);
    if (ret_sf_command_ptosy < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
