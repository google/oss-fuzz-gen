// This fuzz driver is generated for library libsndfile, aiming to fuzz the following functions:
// sf_open at sndfile.c:348:1 in sndfile.h
// sf_writef_int at sndfile.c:2408:1 in sndfile.h
// sf_read_int at sndfile.c:1856:1 in sndfile.h
// sf_format_check at sndfile.c:653:1 in sndfile.h
// sf_write_raw at sndfile.c:2180:1 in sndfile.h
// sf_read_short at sndfile.c:1748:1 in sndfile.h
// sf_read_raw at sndfile.c:1696:1 in sndfile.h
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
#include <cstdio>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(SF_INFO)) return 0;

    // Prepare dummy file
    const char *dummyFileName = "./dummy_file";
    FILE *dummyFile = fopen(dummyFileName, "wb+");
    if (!dummyFile) return 0;
    fwrite(Data, 1, Size, dummyFile);
    fflush(dummyFile);
    rewind(dummyFile);

    // Initialize SF_INFO
    SF_INFO sfinfo;
    memset(&sfinfo, 0, sizeof(SF_INFO));

    // Open the dummy file
    SNDFILE *sndfile = sf_open(dummyFileName, SFM_RDWR, &sfinfo);
    if (!sndfile) {
        fclose(dummyFile);
        return 0;
    }

    // Calculate the number of frames and items
    sf_count_t numFrames = Size / sizeof(int);
    sf_count_t numItems = Size / sizeof(short);

    // Prepare buffers
    int *intBuffer = new int[numFrames];
    short *shortBuffer = new short[numItems];

    // Fuzz sf_writef_int
    sf_writef_int(sndfile, intBuffer, numFrames);

    // Fuzz sf_read_int
    sf_read_int(sndfile, intBuffer, numFrames);

    // Fuzz sf_format_check
    sf_format_check(&sfinfo);

    // Fuzz sf_write_raw
    sf_write_raw(sndfile, Data, Size);

    // Fuzz sf_read_short
    sf_read_short(sndfile, shortBuffer, numItems);

    // Fuzz sf_read_raw
    sf_read_raw(sndfile, shortBuffer, Size);

    // Clean up
    sf_close(sndfile);
    fclose(dummyFile);
    delete[] intBuffer;
    delete[] shortBuffer;
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
    