// This fuzz driver is generated for library libsndfile, aiming to fuzz the following functions:
// sf_open_fd at sndfile.c:440:1 in sndfile.h
// sf_get_string at sndfile.c:1619:1 in sndfile.h
// sf_command at sndfile.c:995:1 in sndfile.h
// sf_set_chunk at sndfile.c:3381:1 in sndfile.h
// sf_set_string at sndfile.c:1631:1 in sndfile.h
// sf_write_sync at sndfile.c:526:1 in sndfile.h
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
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cstdio>
#include <cstring>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

extern "C" int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(SF_INFO) + 1) {
        return 0;
    }

    write_dummy_file(Data, Size);

    int fd = open("./dummy_file", O_RDWR);
    if (fd == -1) {
        return 0;
    }

    SF_INFO sfinfo;
    memcpy(&sfinfo, Data, sizeof(SF_INFO));

    int mode = Data[sizeof(SF_INFO)] % 2 ? SFM_READ : SFM_WRITE;
    int close_desc = 1;

    SNDFILE *sndfile = sf_open_fd(fd, mode, &sfinfo, close_desc);
    if (sndfile) {
        // Test sf_get_string
        const char *str = sf_get_string(sndfile, SF_STR_TITLE);

        // Test sf_command
        int command_result = sf_command(sndfile, SFC_GET_FORMAT_INFO, nullptr, 0);

        // Test sf_set_chunk
        SF_CHUNK_INFO chunk_info;
        memset(&chunk_info, 0, sizeof(SF_CHUNK_INFO));
        int set_chunk_result = sf_set_chunk(sndfile, &chunk_info);

        // Test sf_set_string
        int set_string_result = sf_set_string(sndfile, SF_STR_TITLE, "Fuzz Test Title");

        // Test sf_write_sync
        sf_write_sync(sndfile);

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

        LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    