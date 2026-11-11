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
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "sys/types.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static void prepare_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

extern "C" int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(SF_INFO) + sizeof(int) * 100) {
        return 0;
    }

    // Prepare the dummy file
    prepare_dummy_file(Data, Size);

    // Prepare SF_INFO structure
    SF_INFO sfinfo;
    memcpy(&sfinfo, Data, sizeof(SF_INFO));

    // Open the dummy file
    int fd = open("./dummy_file", O_RDWR);
    if (fd < 0) {
        return 0;
    }

    // Try different modes and close_desc values
    int modes[] = {SFM_READ, SFM_WRITE, SFM_RDWR};
    int close_descs[] = {0, 1};

    for (int mode : modes) {
        for (int close_desc : close_descs) {
            SNDFILE *sndfile = sf_open_fd(fd, mode, &sfinfo, close_desc);
            if (sndfile) {
                // Prepare buffer for writing
                int int_data[100];
                memcpy(int_data, Data + sizeof(SF_INFO), sizeof(int_data));

                double double_data[100];
                memcpy(double_data, Data + sizeof(SF_INFO), sizeof(double_data));

                // Attempt to write using various functions
                sf_writef_int(sndfile, int_data, 100);
                sf_writef_double(sndfile, double_data, 100);
                sf_write_int(sndfile, int_data, 100);
                sf_write_raw(sndfile, Data, Size);

                // Sync writes
                sf_write_sync(sndfile);

                // Close the SNDFILE
                sf_close(sndfile);
            }
        }
    }

    // Close the file descriptor if it's still open
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

    LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
