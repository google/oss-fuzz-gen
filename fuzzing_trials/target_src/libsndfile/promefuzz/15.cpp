// This fuzz driver is generated for library libsndfile, aiming to fuzz the following functions:
// sf_open at sndfile.c:348:1 in sndfile.h
// sf_write_short at sndfile.c:2239:1 in sndfile.h
// sf_writef_int at sndfile.c:2408:1 in sndfile.h
// sf_write_raw at sndfile.c:2180:1 in sndfile.h
// sf_writef_short at sndfile.c:2296:1 in sndfile.h
// sf_read_raw at sndfile.c:1696:1 in sndfile.h
// sf_format_check at sndfile.c:653:1 in sndfile.h
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
#include <cstdio>

static void writeDummyFile(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

extern "C" int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(SF_INFO)) return 0;

    SF_INFO sfinfo;
    std::memcpy(&sfinfo, Data, sizeof(SF_INFO));

    SNDFILE *sndfile = sf_open("./dummy_file", SFM_WRITE, &sfinfo);
    if (!sndfile) return 0;

    // Ensure buffers are large enough to handle potential input sizes
    short shortBuffer[256] = {0};
    int intBuffer[256] = {0};

    sf_count_t items = std::min<sf_count_t>(Size / sizeof(short), 256);
    sf_count_t frames = std::min<sf_count_t>(Size / (sizeof(int) * sfinfo.channels), 256);

    if (items > 0) {
        sf_write_short(sndfile, shortBuffer, items);
    }
    if (frames > 0) {
        sf_writef_int(sndfile, intBuffer, frames);
    }
    if (Size > 0) {
        sf_write_raw(sndfile, Data, Size);
    }
    if (frames > 0) {
        sf_writef_short(sndfile, shortBuffer, frames);
    }

    // Allocate a buffer for reading raw data
    uint8_t readBuffer[256] = {0};
    sf_read_raw(sndfile, readBuffer, sizeof(readBuffer));

    sf_format_check(&sfinfo);

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

        LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    