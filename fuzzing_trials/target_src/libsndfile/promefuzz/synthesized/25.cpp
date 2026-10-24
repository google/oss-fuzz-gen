// This fuzz driver is generated for library libsndfile, aiming to fuzz the following functions:
// sf_open_fd at sndfile.c:440:1 in sndfile.h
// sf_close at sndfile.c:517:1 in sndfile.h
// sf_open_virtual at sndfile.c:472:1 in sndfile.h
// sf_close at sndfile.c:517:1 in sndfile.h
// sf_write_float at sndfile.c:2463:1 in sndfile.h
// sf_write_int at sndfile.c:2351:1 in sndfile.h
// sf_readf_double at sndfile.c:2127:1 in sndfile.h
// sf_error at sndfile.c:591:1 in sndfile.h
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <unistd.h>
#include <fcntl.h>
#include <sndfile.h>

static int create_dummy_file(const uint8_t *Data, size_t Size) {
    int fd = open("./dummy_file", O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return -1;
    }
    if (write(fd, Data, Size) != (ssize_t)Size) {
        close(fd);
        return -1;
    }
    lseek(fd, 0, SEEK_SET);
    return fd;
}

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(SF_INFO) + sizeof(SF_VIRTUAL_IO)) {
        return 0;
    }

    SF_INFO sfinfo;
    memcpy(&sfinfo, Data, sizeof(SF_INFO));

    int fd = create_dummy_file(Data, Size);
    if (fd < 0) {
        return 0;
    }

    SNDFILE *sndfile_fd = sf_open_fd(fd, SFM_READ, &sfinfo, 1);
    if (sndfile_fd) {
        sf_close(sndfile_fd);
    }

    // Initialize SF_VIRTUAL_IO with dummy functions
    SF_VIRTUAL_IO sfvirtual;
    memset(&sfvirtual, 0, sizeof(SF_VIRTUAL_IO));
    sfvirtual.get_filelen = [](void *user_data) -> sf_count_t { return 0; };
    sfvirtual.seek = [](sf_count_t offset, int whence, void *user_data) -> sf_count_t { return 0; };
    sfvirtual.read = [](void *ptr, sf_count_t count, void *user_data) -> sf_count_t { return 0; };
    sfvirtual.write = [](const void *ptr, sf_count_t count, void *user_data) -> sf_count_t { return 0; };
    sfvirtual.tell = [](void *user_data) -> sf_count_t { return 0; };

    SNDFILE *sndfile_virtual = sf_open_virtual(&sfvirtual, SFM_READ, &sfinfo, nullptr);
    if (sndfile_virtual) {
        sf_close(sndfile_virtual);
    }

    if (sndfile_fd) {
        float float_buffer[256] = {0};
        sf_write_float(sndfile_fd, float_buffer, 256);

        int int_buffer[256] = {0};
        sf_write_int(sndfile_fd, int_buffer, 256);

        double double_buffer[256] = {0};
        sf_readf_double(sndfile_fd, double_buffer, 256);

        sf_error(sndfile_fd);
    }

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

        LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    