// This fuzz driver is generated for library libsndfile, aiming to fuzz the following functions:
// sf_open at sndfile.c:348:1 in sndfile.h
// sf_read_double at sndfile.c:2072:1 in sndfile.h
// sf_read_float at sndfile.c:1964:1 in sndfile.h
// sf_readf_float at sndfile.c:2019:1 in sndfile.h
// sf_readf_short at sndfile.c:1803:1 in sndfile.h
// sf_write_float at sndfile.c:2463:1 in sndfile.h
// sf_writef_float at sndfile.c:2520:1 in sndfile.h
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
#include <cstdlib>
#include <cstring>
#include <cstdio>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

extern "C" int LLVMFuzzerTestOneInput_27(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(SF_INFO)) {
        return 0;
    }

    write_dummy_file(Data, Size);

    SF_INFO sfinfo;
    memset(&sfinfo, 0, sizeof(SF_INFO));
    SNDFILE *sndfile = sf_open("./dummy_file", SFM_RDWR, &sfinfo);
    if (!sndfile) {
        return 0;
    }

    sf_count_t num_items = Size / sizeof(double);
    double *dbl_buffer = (double *)malloc(num_items * sizeof(double));
    float *flt_buffer = (float *)malloc(num_items * sizeof(float));
    short *sht_buffer = (short *)malloc(num_items * sizeof(short));

    if (dbl_buffer && flt_buffer && sht_buffer) {
        sf_read_double(sndfile, dbl_buffer, num_items);
        sf_read_float(sndfile, flt_buffer, num_items);
        sf_readf_float(sndfile, flt_buffer, num_items);
        sf_readf_short(sndfile, sht_buffer, num_items);

        sf_write_float(sndfile, flt_buffer, num_items);
        sf_writef_float(sndfile, flt_buffer, num_items);
    }

    free(dbl_buffer);
    free(flt_buffer);
    free(sht_buffer);

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
    