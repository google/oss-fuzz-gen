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
#include <cstdio>
#include <cstdlib>

static void writeDummyFile(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(SF_INFO)) return 0;

    SF_INFO sfinfo;
    memcpy(&sfinfo, Data, sizeof(SF_INFO));

    // Write dummy data to a file
    writeDummyFile(Data, Size);

    SNDFILE *sndfile = sf_open("./dummy_file", SFM_RDWR, &sfinfo);
    if (!sndfile) return 0;

    int *intBuffer = (int *)malloc(Size * sizeof(int));
    double *doubleBuffer = (double *)malloc(Size * sizeof(double));
    if (!intBuffer || !doubleBuffer) {
        sf_close(sndfile);
        free(intBuffer);
        free(doubleBuffer);
        return 0;
    }

    // sf_writef_int
    sf_writef_int(sndfile, intBuffer, Size / sizeof(int));

    // sf_read_int
    sf_read_int(sndfile, intBuffer, Size / sizeof(int));

    // sf_format_check
    sf_format_check(&sfinfo);

    // sf_read_double
    sf_read_double(sndfile, doubleBuffer, Size / sizeof(double));

    // sf_write_raw
    sf_write_raw(sndfile, Data, Size);

    // sf_read_raw
    sf_read_raw(sndfile, intBuffer, Size);

    sf_close(sndfile);
    free(intBuffer);
    free(doubleBuffer);

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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
