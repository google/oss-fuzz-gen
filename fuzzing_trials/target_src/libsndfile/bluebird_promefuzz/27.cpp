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
#include <cstring>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput_27(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(SF_INFO)) {
        return 0;
    }

    SF_INFO sfinfo;
    std::memcpy(&sfinfo, Data, sizeof(SF_INFO));

    SNDFILE *sndfile = sf_open("./dummy_file", SFM_READ, &sfinfo);
    if (!sndfile) {
        return 0;
    }

    // Adjust buffer size based on the number of channels to avoid overflow
    size_t bufferSize = 1024 * sfinfo.channels;
    double *dblBuffer = new double[bufferSize];
    int *intBuffer = new int[bufferSize];
    float *fltBuffer = new float[bufferSize];
    short *shtBuffer = new short[bufferSize];

    sf_count_t items = bufferSize;

    // Fuzz sf_read_double
    sf_count_t readDoubles = sf_read_double(sndfile, dblBuffer, items);

    // Fuzz sf_read_int
    sf_count_t readInts = sf_read_int(sndfile, intBuffer, items);

    // Fuzz sf_read_float
    sf_count_t readFloats = sf_read_float(sndfile, fltBuffer, items);

    // Fuzz sf_readf_float
    sf_count_t readfFloats = sf_readf_float(sndfile, fltBuffer, items / sfinfo.channels);

    // Fuzz sf_readf_short
    sf_count_t readfShorts = sf_readf_short(sndfile, shtBuffer, items / sfinfo.channels);

    // Fuzz sf_read_short

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sf_readf_short to sf_write_double
    // Ensure dataflow is valid (i.e., non-null)
    if (!sndfile) {
    	return 0;
    }
    int ret_sf_error_dhsoe = sf_error(sndfile);
    if (ret_sf_error_dhsoe < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!sndfile) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!shtBuffer) {
    	return 0;
    }
    sf_count_t ret_sf_write_double_zcjyq = sf_write_double(sndfile, (const double *)shtBuffer, -1);
    if (ret_sf_write_double_zcjyq < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    sf_count_t readShorts = sf_read_short(sndfile, shtBuffer, items);


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sf_read_short to sf_open
    const char rwxdctjr[1024] = "vudeo";
    SNDFILE* ret_sf_open_ggxxn = sf_open(rwxdctjr, (int )*shtBuffer, NULL);
    if (ret_sf_open_ggxxn == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    delete[] dblBuffer;
    delete[] intBuffer;
    delete[] fltBuffer;
    delete[] shtBuffer;

    sf_close(sndfile);
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

    LLVMFuzzerTestOneInput_27(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
