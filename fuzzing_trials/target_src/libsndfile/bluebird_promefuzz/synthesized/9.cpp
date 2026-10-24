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
#include <cstdio>

extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double)) {
        return 0;
    }

    SF_INFO sfinfo;
    memset(&sfinfo, 0, sizeof(SF_INFO));
    sfinfo.samplerate = 44100;
    sfinfo.channels = 2;
    sfinfo.format = SF_FORMAT_WAV | SF_FORMAT_PCM_16;

    // Write to a dummy file
    SNDFILE *sndfile = sf_open("./dummy_file", SFM_WRITE, &sfinfo);
    if (!sndfile) {
        return 0;
    }

    // Use a portion of the input data as double buffer
    size_t double_count = Size / sizeof(double);
    double *double_data = reinterpret_cast<double *>(const_cast<uint8_t *>(Data));

    // Fuzz sf_writef_double
    sf_count_t written_frames = sf_writef_double(sndfile, double_data, double_count / sfinfo.channels);
    if (written_frames < 0) {
        sf_error(sndfile);
    }

    // Prepare integer buffer for sf_readf_int
    int *int_data = new int[double_count];
    sf_seek(sndfile, 0, SEEK_SET); // Reset file pointer for reading

    // Fuzz sf_readf_int
    sf_count_t read_frames = sf_readf_int(sndfile, int_data, double_count / sfinfo.channels);
    if (read_frames < 0) {
        sf_error(sndfile);
    }

    // Fuzz sf_write_int
    sf_seek(sndfile, 0, SEEK_SET); // Reset file pointer for writing
    sf_count_t written_items = sf_write_int(sndfile, int_data, double_count);
    if (written_items < 0) {
        sf_error(sndfile);
    }

    // Fuzz sf_seek
    sf_seek(sndfile, 0, SEEK_END);

    // Fuzz sf_readf_double
    sf_seek(sndfile, 0, SEEK_SET);
    sf_count_t read_double_frames = sf_readf_double(sndfile, double_data, double_count / sfinfo.channels);
    if (read_double_frames < 0) {
        sf_error(sndfile);
    }

    // Clean up
    sf_close(sndfile);
    delete[] int_data;
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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
