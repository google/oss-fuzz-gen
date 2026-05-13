// This fuzz driver is generated for library libsndfile, aiming to fuzz the following functions:
// sf_open_fd at sndfile.c:440:1 in sndfile.h
// sf_readf_int at sndfile.c:1911:1 in sndfile.h
// sf_writef_int at sndfile.c:2408:1 in sndfile.h
// sf_read_int at sndfile.c:1856:1 in sndfile.h
// sf_write_int at sndfile.c:2351:1 in sndfile.h
// sf_error at sndfile.c:591:1 in sndfile.h
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
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>

static void writeDummyFile(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(SF_INFO)) {
        return 0;
    }

    SF_INFO sfinfo = {};
    writeDummyFile(Data, Size);
    int fd = open("./dummy_file", O_RDWR);
    if (fd == -1) {
        return 0;
    }

    int mode = SFM_READ;
    int close_desc = 1;

    SNDFILE *sndfile = sf_open_fd(fd, mode, &sfinfo, close_desc);
    if (sndfile) {
        int buffer[1024];
        sf_count_t frames = 1024;

        sf_readf_int(sndfile, buffer, frames);
        sf_writef_int(sndfile, buffer, frames);
        sf_read_int(sndfile, buffer, frames);
        sf_write_int(sndfile, buffer, frames);

        int error = sf_error(sndfile);
        (void)error; // Suppress unused variable warning

        sf_close(sndfile);
    } else {
        close(fd);
    }

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
    