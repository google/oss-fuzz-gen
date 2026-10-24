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
#include "magic.h"
#include <cstdint>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize magic cookie
    magic_t cookie = magic_open(MAGIC_NONE);
    if (!cookie) return 0;

    // Load dummy magic database
    void *buffers[] = { (void *)Data };
    size_t buffer_sizes[] = { Size };
    if (magic_load_buffers(cookie, buffers, buffer_sizes, 1) == -1) {
        magic_close(cookie);
        return 0;
    }

    // Fuzz magic_setparam
    int param = Data[0] % 10; // Arbitrary parameter choice
    magic_setparam(cookie, param, (void *)&Size);

    // Fuzz magic_setflags
    int flags = Data[0] % 10; // Arbitrary flag choice
    magic_setflags(cookie, flags);

    // Fuzz magic_getflags
    magic_getflags(cookie);

    // Fuzz magic_errno
    magic_errno(cookie);

    // Write data to a dummy file and get a file descriptor
    int fd = open("./dummy_file", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd != -1) {
        write(fd, Data, Size);
        lseek(fd, 0, SEEK_SET); // Reset file descriptor position

        // Fuzz magic_descriptor
        magic_descriptor(cookie, fd);

        close(fd);
    }

    // Cleanup
    magic_close(cookie);
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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
