// This fuzz driver is generated for library libsndfile, aiming to fuzz the following functions:
// sf_open_fd at sndfile.c:440:1 in sndfile.h
// sf_close at sndfile.c:517:1 in sndfile.h
// sf_open at sndfile.c:348:1 in sndfile.h
// sf_close at sndfile.c:517:1 in sndfile.h
// sf_format_check at sndfile.c:653:1 in sndfile.h
// sf_command at sndfile.c:995:1 in sndfile.h
// sf_set_chunk at sndfile.c:3381:1 in sndfile.h
// sf_set_string at sndfile.c:1631:1 in sndfile.h
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
#include <fcntl.h>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(SF_INFO)) {
        return 0;
    }

    // Prepare SF_INFO structure
    SF_INFO sfinfo;
    sfinfo.frames = *(reinterpret_cast<const sf_count_t*>(Data));
    sfinfo.samplerate = *(reinterpret_cast<const int*>(Data + sizeof(sf_count_t)));

    // Prepare dummy file
    const char *dummyFilePath = "./dummy_file";
    int fd = open(dummyFilePath, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return 0;
    }

    // Explore sf_open_fd
    int mode = SFM_READ;
    int closeDesc = 1;
    SNDFILE *sndfile = sf_open_fd(fd, mode, &sfinfo, closeDesc);
    if (sndfile) {
        sf_close(sndfile);
    }

    // Explore sf_open
    sndfile = sf_open(dummyFilePath, mode, &sfinfo);
    if (sndfile) {
        sf_close(sndfile);
    }

    // Explore sf_format_check
    int formatCheck = sf_format_check(&sfinfo);

    // Explore sf_command
    int command = SFC_GET_LIB_VERSION;
    char libVersion[64];
    int commandResult = sf_command(sndfile, command, libVersion, sizeof(libVersion));

    // Prepare SF_CHUNK_INFO structure
    SF_CHUNK_INFO chunkInfo;
    chunkInfo.id_size = 64;
    chunkInfo.data = malloc(64);
    if (chunkInfo.data) {
        // Explore sf_set_chunk
        int chunkResult = sf_set_chunk(sndfile, &chunkInfo);
        free(chunkInfo.data);
    }

    // Explore sf_set_string
    int strType = SF_STR_TITLE;
    const char *strValue = "Test Title";
    int setStringResult = sf_set_string(sndfile, strType, strValue);

    close(fd);
    unlink(dummyFilePath);

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

        LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    