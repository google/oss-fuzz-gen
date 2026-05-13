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

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(SF_INFO)) {
        return 0;
    }

    SF_INFO sfinfo;
    std::memcpy(&sfinfo, Data, sizeof(SF_INFO));

    SNDFILE *sndfile = sf_open("./dummy_file", SFM_WRITE, &sfinfo);
    if (!sndfile) {
        return 0;
    }

    size_t remaining_size = Size - sizeof(SF_INFO);
    const uint8_t *data_ptr = Data + sizeof(SF_INFO);

    // Fuzz sf_write_short
    if (remaining_size >= sizeof(short)) {
        sf_count_t items_to_write = remaining_size / sizeof(short);
        sf_write_short(sndfile, reinterpret_cast<const short *>(data_ptr), items_to_write);
    }

    // Fuzz sf_writef_int
    if (remaining_size >= sizeof(int)) {
        sf_count_t frames_to_write = remaining_size / (sizeof(int) * sfinfo.channels);
        if (frames_to_write > 0) {
            sf_writef_int(sndfile, reinterpret_cast<const int *>(data_ptr), frames_to_write);
        }
    }

    // Fuzz sf_write_raw
    sf_write_raw(sndfile, data_ptr, remaining_size);

    // Fuzz sf_writef_short
    if (remaining_size >= sizeof(short)) {
        sf_count_t frames_to_write = remaining_size / (sizeof(short) * sfinfo.channels);
        if (frames_to_write > 0) {
            sf_writef_short(sndfile, reinterpret_cast<const short *>(data_ptr), frames_to_write);
        }
    }

    // Fuzz sf_readf_short
    if (remaining_size >= sizeof(short)) {
        short *buffer = new short[remaining_size / sizeof(short)];
        sf_readf_short(sndfile, buffer, remaining_size / sizeof(short));
        delete[] buffer;
    }

    // Fuzz sf_write_sync
    sf_write_sync(sndfile);

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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
