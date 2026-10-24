// This fuzz driver is generated for library htslib, aiming to fuzz the following functions:
// hopen at hfile.c:1304:8 in hfile.h
// hfile_set_blksize at hfile.c:213:5 in hfile.h
// hwrite at hfile.h:280:1 in hfile.h
// hclose_abruptly at hfile.c:507:6 in hfile.h
// herrno at hfile.h:134:19 in hfile.h
// hclose_abruptly at hfile.c:507:6 in hfile.h
// hclose_abruptly at hfile.c:507:6 in hfile.h
// hdopen at hfile.c:722:8 in hfile.h
// herrno at hfile.h:134:19 in hfile.h
// hclose_abruptly at hfile.c:507:6 in hfile.h
// hclose_abruptly at hfile.c:507:6 in hfile.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "hfile.h"

#define DUMMY_FILE "./dummy_file"

static void write_dummy_data(const uint8_t *Data, size_t Size) {
    FILE *f = fopen(DUMMY_FILE, "wb");
    if (f) {
        fwrite(Data, 1, Size, f);
        fclose(f);
    }
}

int LLVMFuzzerTestOneInput_37(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Write the data to a dummy file
    write_dummy_data(Data, Size);

    // Open the dummy file using hopen
    hFILE *file = hopen(DUMMY_FILE, "rb");
    if (!file) return 0;

    // Test hfile_set_blksize
    size_t new_blksize = Size % 1024; // Random block size for testing
    hfile_set_blksize(file, new_blksize);

    // Test hwrite
    ssize_t bytes_written = hwrite(file, Data, Size);
    if (bytes_written < 0) {
        hclose_abruptly(file);
        return 0;
    }

    // Check error status using herrno
    int error = herrno(file);
    if (error) {
        hclose_abruptly(file);
        return 0;
    }

    // Close the file abruptly
    hclose_abruptly(file);

    // Reopen the file descriptor
    int fd = open(DUMMY_FILE, O_RDONLY);
    if (fd < 0) return 0;

    // Use hdopen to associate hFILE with the file descriptor
    hFILE *file2 = hdopen(fd, "rb");
    if (!file2) {
        close(fd);
        return 0;
    }

    // Check error status using herrno again
    error = herrno(file2);
    if (error) {
        hclose_abruptly(file2);
        return 0;
    }

    // Close the file abruptly again
    hclose_abruptly(file2);

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

    LLVMFuzzerTestOneInput_37(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
