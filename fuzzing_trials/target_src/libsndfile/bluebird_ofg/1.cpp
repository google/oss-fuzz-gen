#include <sys/stat.h>
#include "sndfile.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include <unistd.h>
    #include <fcntl.h>
}

extern "C" int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    // Create a temporary file to write the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Close the file descriptor after writing
    close(fd);

    // Open the file with libsndfile
    SF_INFO sfinfo;
    memset(&sfinfo, 0, sizeof(SF_INFO));
    SNDFILE *sndfile = sf_open(tmpl, SFM_READ, &sfinfo);
    if (sndfile == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Allocate buffer for reading samples
    sf_count_t num_samples = 1024; // Arbitrary number for buffer size
    short *buffer = (short *)malloc(num_samples * sizeof(short));
    if (buffer == NULL) {
        sf_close(sndfile);
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    sf_read_short(sndfile, buffer, num_samples);

    // Clean up

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from sf_read_short to sf_open_fd using the plateau pool

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sf_read_short to sf_read_double
    // Ensure dataflow is valid (i.e., non-null)
    if (!sndfile) {
    	return 0;
    }
    int ret_sf_perror_omqcx = sf_perror(sndfile);
    if (ret_sf_perror_omqcx < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!sndfile) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!buffer) {
    	return 0;
    }
    sf_count_t ret_sf_read_double_xbbcj = sf_read_double(sndfile, (double *)buffer, 64);
    if (ret_sf_read_double_xbbcj < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    SNDFILE* ret_sf_open_fd_vyvre = sf_open_fd(fd, SFM_WRITE, &sfinfo, (int )*buffer);
    if (ret_sf_open_fd_vyvre == NULL){
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

    LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
