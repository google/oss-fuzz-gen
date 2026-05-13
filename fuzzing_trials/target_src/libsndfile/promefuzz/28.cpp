// This fuzz driver is generated for library libsndfile, aiming to fuzz the following functions:
// sf_open at sndfile.c:348:1 in sndfile.h
// sf_read_double at sndfile.c:2072:1 in sndfile.h
// sf_read_float at sndfile.c:1964:1 in sndfile.h
// sf_readf_float at sndfile.c:2019:1 in sndfile.h
// sf_readf_short at sndfile.c:1803:1 in sndfile.h
// sf_close at sndfile.c:517:1 in sndfile.h
// sf_open at sndfile.c:348:1 in sndfile.h
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
#include <iostream>

static void writeDummyFile(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

extern "C" int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(SF_INFO)) {
        return 0;
    }

    // Prepare the SF_INFO structure
    SF_INFO sfinfo;
    memcpy(&sfinfo, Data, sizeof(SF_INFO));

    // Write the dummy file
    writeDummyFile(Data + sizeof(SF_INFO), Size - sizeof(SF_INFO));

    // Open the dummy file
    SNDFILE *sndfile = sf_open("./dummy_file", SFM_READ, &sfinfo);
    if (!sndfile) {
        return 0;
    }

    // Buffers for different data types
    double *doubleBuffer = new double[sfinfo.frames];
    float *floatBuffer = new float[sfinfo.frames];
    short *shortBuffer = new short[sfinfo.frames];

    // Fuzz sf_read_double
    sf_read_double(sndfile, doubleBuffer, sfinfo.frames);

    // Fuzz sf_read_float
    sf_read_float(sndfile, floatBuffer, sfinfo.frames);

    // Fuzz sf_readf_float
    sf_readf_float(sndfile, floatBuffer, sfinfo.frames);

    // Fuzz sf_readf_short
    sf_readf_short(sndfile, shortBuffer, sfinfo.frames);

    // Reopen the file in write mode for sf_write_float and sf_writef_float
    sf_close(sndfile);
    sndfile = sf_open("./dummy_file", SFM_WRITE, &sfinfo);
    if (sndfile) {
        // Fuzz sf_write_float
        sf_write_float(sndfile, floatBuffer, sfinfo.frames);

        // Fuzz sf_writef_float
        sf_writef_float(sndfile, floatBuffer, sfinfo.frames);

        sf_close(sndfile);
    }

    // Clean up
    delete[] doubleBuffer;
    delete[] floatBuffer;
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

        LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    