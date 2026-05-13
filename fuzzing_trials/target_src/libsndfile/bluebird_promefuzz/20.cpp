#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include "sndfile.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(SF_INFO)) {
        return 0;
    }

    SF_INFO sfinfo;
    std::memset(&sfinfo, 0, sizeof(SF_INFO));

    // Write dummy data to a file
    const char *filename = "./dummy_file";
    FILE *file = std::fopen(filename, "wb");
    if (!file) {
        return 0;
    }
    std::fwrite(Data, 1, Size, file);
    std::fclose(file);

    // Open the file with libsndfile
    SNDFILE *sndfile = sf_open(filename, SFM_READ, &sfinfo);
    if (!sndfile) {
        return 0;
    }

    // Prepare buffers for reading
    sf_count_t frames_to_read = 1024; // Arbitrary number of frames to attempt to read
    short *short_buffer = new short[frames_to_read * sfinfo.channels];
    int *int_buffer = new int[frames_to_read * sfinfo.channels];
    double *double_buffer = new double[frames_to_read * sfinfo.channels];

    // Invoke sf_read_short
    sf_read_short(sndfile, short_buffer, frames_to_read);

    // Invoke sf_read_int

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sf_read_short to sf_command
    // Ensure dataflow is valid (i.e., non-null)
    if (!sndfile) {
    	return 0;
    }
    const char* ret_sf_strerror_ixqnh = sf_strerror(sndfile);
    if (ret_sf_strerror_ixqnh == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!sndfile) {
    	return 0;
    }
    int ret_sf_perror_fgfif = sf_perror(sndfile);
    if (ret_sf_perror_fgfif < 0){
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
    int ret_sf_command_jecdo = sf_command(sndfile, (int )*short_buffer, (void *)sndfile, -1);
    if (ret_sf_command_jecdo < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    sf_read_int(sndfile, int_buffer, frames_to_read);

    // Invoke sf_read_double
    sf_read_double(sndfile, double_buffer, frames_to_read);

    // Clean up
    sf_close(sndfile);
    delete[] short_buffer;
    delete[] int_buffer;
    delete[] double_buffer;

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

    LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
