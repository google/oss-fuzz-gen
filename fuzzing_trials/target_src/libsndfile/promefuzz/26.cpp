// This fuzz driver is generated for library libsndfile, aiming to fuzz the following functions:
// sf_open at sndfile.c:348:1 in sndfile.h
// sf_read_double at sndfile.c:2072:1 in sndfile.h
// sf_read_int at sndfile.c:1856:1 in sndfile.h
// sf_write_float at sndfile.c:2463:1 in sndfile.h
// sf_readf_float at sndfile.c:2019:1 in sndfile.h
// sf_read_float at sndfile.c:1964:1 in sndfile.h
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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(SF_INFO)) {
        return 0;
    }

    SF_INFO sfinfo;
    memcpy(&sfinfo, Data, sizeof(SF_INFO));

    // Create a dummy file to simulate reading/writing
    const char *dummyFile = "./dummy_file";
    FILE *file = fopen(dummyFile, "wb+");
    if (!file) {
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    SNDFILE *sndfile = sf_open(dummyFile, SFM_RDWR, &sfinfo);
    if (!sndfile) {
        return 0;
    }

    // Buffers for reading/writing
    double *doubleBuffer = new double[sfinfo.frames];
    int *intBuffer = new int[sfinfo.frames];
    float *floatBuffer = new float[sfinfo.frames];

    // Fuzz sf_read_double
    sf_read_double(sndfile, doubleBuffer, sfinfo.frames);

    // Fuzz sf_read_int
    sf_read_int(sndfile, intBuffer, sfinfo.frames);

    // Fuzz sf_write_float
    sf_write_float(sndfile, floatBuffer, sfinfo.frames);

    // Fuzz sf_readf_float
    sf_readf_float(sndfile, floatBuffer, sfinfo.frames);

    // Fuzz sf_read_float
    sf_read_float(sndfile, floatBuffer, sfinfo.frames);

    // Fuzz sf_writef_float
    sf_writef_float(sndfile, floatBuffer, sfinfo.frames);

    // Cleanup
    sf_close(sndfile);
    delete[] doubleBuffer;
    delete[] intBuffer;
    delete[] floatBuffer;

    // Remove dummy file
    remove(dummyFile);

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

        LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    