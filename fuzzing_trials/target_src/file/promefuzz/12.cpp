// This fuzz driver is generated for library file, aiming to fuzz the following functions:
// magic_open at magic.c:267:1 in magic.h
// magic_setparam at magic.c:613:1 in magic.h
// magic_load_buffers at magic.c:329:1 in magic.h
// magic_getparam at magic.c:656:1 in magic.h
// magic_errno at magic.c:577:1 in magic.h
// magic_compile at magic.c:340:1 in magic.h
// magic_setflags at magic.c:594:1 in magic.h
// magic_close at magic.c:306:1 in magic.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <magic.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>

extern "C" int LLVMFuzzerTestOneInput_12(const uint8_t *Data, size_t Size) {
    // Initialize a magic cookie
    magic_t cookie = magic_open(MAGIC_NONE);
    if (!cookie) {
        return 0;
    }

    // Attempt to set a parameter
    if (Size >= sizeof(int)) {
        int param = *reinterpret_cast<const int*>(Data);
        magic_setparam(cookie, param, Data + sizeof(int));
    }

    // Attempt to load buffers
    if (Size > 0) {
        void *buffers[] = {const_cast<uint8_t*>(Data)};
        size_t buffer_sizes[] = {Size};
        magic_load_buffers(cookie, buffers, buffer_sizes, 1);
    }

    // Attempt to get a parameter
    if (Size >= sizeof(int) + sizeof(size_t)) {
        int param = *reinterpret_cast<const int*>(Data);
        size_t val;
        magic_getparam(cookie, param, &val);
    }

    // Check for errors
    int err = magic_errno(cookie);

    // Attempt to compile
    const char *filename = "./dummy_file";
    int fd = open(filename, O_CREAT | O_WRONLY, 0644);
    if (fd != -1) {
        write(fd, Data, Size);
        close(fd);
        magic_compile(cookie, filename);
        unlink(filename);
    }

    // Attempt to set flags
    if (Size >= sizeof(int)) {
        int flags = *reinterpret_cast<const int*>(Data);
        magic_setflags(cookie, flags);
    }

    // Clean up
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

        LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    