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
extern "C" {
#include "sndfile.h"
#include <fcntl.h>
#include <unistd.h>
}

#include <cstdint>
#include <cstdio>
#include <cstdlib>

static void fuzz_sf_open_fd(int fd, const uint8_t *Data, size_t Size) {
    SF_INFO sfinfo;
    sfinfo.frames = 0;
    sfinfo.samplerate = 0;
    sfinfo.channels = 0;
    sfinfo.format = 0;
    sfinfo.sections = 0;
    sfinfo.seekable = 0;

    int mode = (Size > 0) ? (Data[0] % 2 == 0 ? SFM_READ : SFM_WRITE) : SFM_RDWR;
    int close_desc = (Size > 1) ? (Data[1] % 2 == 0 ? 1 : 0) : 0;

    SNDFILE* sndfile = sf_open_fd(fd, mode, &sfinfo, close_desc);
    if (sndfile) {
        sf_close(sndfile);
    }
}

static void fuzz_sf_command(SNDFILE *sndfile, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return;
    }

    int command = *(reinterpret_cast<const int*>(Data));
    void *data = nullptr;
    int datasize = 0;
    sf_command(sndfile, command, data, datasize);
}

static void fuzz_sf_error_number(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return;
    }

    int errnum = *(reinterpret_cast<const int*>(Data));
    sf_error_number(errnum);
}

static void fuzz_sf_strerror(SNDFILE *sndfile) {
    sf_strerror(sndfile);
}

static void fuzz_sf_error(SNDFILE *sndfile) {
    sf_error(sndfile);
}

static void fuzz_sf_perror(SNDFILE *sndfile) {
    sf_perror(sndfile);
}

extern "C" int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size) {
    int fd = open("./dummy_file", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return 0;
    }

    if (write(fd, Data, Size) != static_cast<ssize_t>(Size)) {
        close(fd);
        return 0;
    }

    lseek(fd, 0, SEEK_SET);

    fuzz_sf_open_fd(fd, Data, Size);

    SF_INFO sfinfo;
    sfinfo.frames = 0;
    sfinfo.samplerate = 0;
    sfinfo.channels = 0;
    sfinfo.format = 0;
    sfinfo.sections = 0;
    sfinfo.seekable = 0;

    SNDFILE *sndfile = sf_open_fd(fd, SFM_READ, &sfinfo, 1);
    if (sndfile) {
        fuzz_sf_command(sndfile, Data, Size);
        fuzz_sf_strerror(sndfile);
        fuzz_sf_error(sndfile);
        fuzz_sf_perror(sndfile);
        // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function sf_close with sf_perror
        sf_perror(sndfile);
        // End mutation: Producer.REPLACE_FUNC_MUTATOR
    }

    fuzz_sf_error_number(Data, Size);

    close(fd);
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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
