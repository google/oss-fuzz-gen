#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "htslib/hfile.h"

#define DUMMY_FILE "./dummy_file"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen(DUMMY_FILE, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare dummy file with input data
    write_dummy_file(Data, Size);

    // Attempt to open the dummy file using hopen
    hFILE *file = hopen(DUMMY_FILE, "rb");
    if (!file) return 0;

    // Set a random block size
    size_t block_size = Size % 1024 + 1; // Block size between 1 and 1024
    hfile_set_blksize(file, block_size);

    // Prepare a buffer for hwrite
    char buffer[1024];
    size_t to_write = Size < sizeof(buffer) ? Size : sizeof(buffer);

    // Attempt to write data to the file
    ssize_t written = hwrite(file, Data, to_write);

    // Check for errors using herrno
    if (herrno(file)) {
        hclose_abruptly(file);
        return 0;
    }

    // Close the file abruptly
    hclose_abruptly(file);

    // Attempt to open a file descriptor using hdopen
    int fd = open(DUMMY_FILE, O_RDONLY);
    if (fd != -1) {
        hFILE *fd_file = hdopen(fd, "rb");
        if (fd_file) {
            // Perform some operations
            hfile_set_blksize(fd_file, block_size);
            hclose_abruptly(fd_file);
        } else {
            close(fd);
        }
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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
