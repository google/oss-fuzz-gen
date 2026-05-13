// This fuzz driver is generated for library libsndfile, aiming to fuzz the following functions:
// sf_open_fd at sndfile.c:440:1 in sndfile.h
// sf_close at sndfile.c:517:1 in sndfile.h
// sf_format_check at sndfile.c:653:1 in sndfile.h
// sf_command at sndfile.c:995:1 in sndfile.h
// sf_set_chunk at sndfile.c:3381:1 in sndfile.h
// sf_seek at sndfile.c:1501:1 in sndfile.h
// sf_version_string at sndfile.c:981:1 in sndfile.h
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
#include <fcntl.h>
#include <unistd.h>

static void fuzz_sf_open_fd(const uint8_t *Data, size_t Size) {
    int fd = open("./dummy_file", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) return;

    if (write(fd, Data, Size) != static_cast<ssize_t>(Size)) {
        close(fd);
        return;
    }

    lseek(fd, 0, SEEK_SET);

    SF_INFO sfinfo = {0};
    int mode = SFM_READ;
    int close_desc = 1;

    SNDFILE *sndfile = sf_open_fd(fd, mode, &sfinfo, close_desc);
    if (sndfile) {
        sf_close(sndfile);
    } else {
        close(fd);
    }
}

static void fuzz_sf_format_check(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(SF_INFO)) return;

    SF_INFO sfinfo;
    memcpy(&sfinfo, Data, sizeof(SF_INFO));

    sf_format_check(&sfinfo);
}

static void fuzz_sf_command(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return;

    int command;
    memcpy(&command, Data, sizeof(int));

    SNDFILE *sndfile = nullptr;
    void *data = nullptr;
    int datasize = 0;

    sf_command(sndfile, command, data, datasize);
}

static void fuzz_sf_set_chunk(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(SF_CHUNK_INFO)) return;

    SF_CHUNK_INFO chunk_info;
    memcpy(&chunk_info, Data, sizeof(SF_CHUNK_INFO));

    SNDFILE *sndfile = nullptr;

    sf_set_chunk(sndfile, &chunk_info);
}

static void fuzz_sf_seek(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(sf_count_t) + sizeof(int)) return;

    sf_count_t frames;
    int whence;
    memcpy(&frames, Data, sizeof(sf_count_t));
    memcpy(&whence, Data + sizeof(sf_count_t), sizeof(int));

    SNDFILE *sndfile = nullptr;

    sf_seek(sndfile, frames, whence);
}

static void fuzz_sf_version_string() {
    sf_version_string();
}

extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size) {
    fuzz_sf_open_fd(Data, Size);
    fuzz_sf_format_check(Data, Size);
    fuzz_sf_command(Data, Size);
    fuzz_sf_set_chunk(Data, Size);
    fuzz_sf_seek(Data, Size);
    fuzz_sf_version_string();

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

        LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    