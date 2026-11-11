// This fuzz driver is generated for library libsndfile, aiming to fuzz the following functions:
// sf_open at sndfile.c:348:1 in sndfile.h
// sf_read_double at sndfile.c:2072:1 in sndfile.h
// sf_read_int at sndfile.c:1856:1 in sndfile.h
// sf_read_float at sndfile.c:1964:1 in sndfile.h
// sf_readf_float at sndfile.c:2019:1 in sndfile.h
// sf_readf_short at sndfile.c:1803:1 in sndfile.h
// sf_read_short at sndfile.c:1748:1 in sndfile.h
// sf_close at sndfile.c:517:1 in sndfile.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <sndfile.h>
#include <cstdint>
#include <cstring>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(SF_INFO)) return 0;

    SF_INFO sfinfo;
    std::memcpy(&sfinfo, Data, sizeof(SF_INFO));

    SNDFILE *sndfile = sf_open("./dummy_file", SFM_READ, &sfinfo);
    if (!sndfile) return 0;

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
    sf_count_t readShorts = sf_read_short(sndfile, shtBuffer, items);

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

        LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    