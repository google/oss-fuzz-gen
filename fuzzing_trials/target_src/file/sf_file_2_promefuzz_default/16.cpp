// This fuzz driver is generated for library file, aiming to fuzz the following functions:
// magic_getpath at magic.c:255:1 in magic.h
// magic_open at magic.c:268:1 in magic.h
// magic_compile at magic.c:341:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
// magic_open at magic.c:268:1 in magic.h
// magic_check at magic.c:349:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
// magic_open at magic.c:268:1 in magic.h
// magic_buffer at magic.c:552:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
// magic_open at magic.c:268:1 in magic.h
// magic_list at magic.c:357:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
// magic_open at magic.c:268:1 in magic.h
// magic_descriptor at magic.c:404:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
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
#include <fcntl.h>
#include <unistd.h>

static void fuzz_magic_getpath(const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        char *path = new char[Size + 1];
        memcpy(path, Data, Size);
        path[Size] = '\0';
        magic_getpath(path, 0);
        delete[] path;
    }
}

static void fuzz_magic_compile(const uint8_t *Data, size_t Size) {
    magic_t magic = magic_open(0);
    if (magic) {
        if (Size > 0) {
            FILE *file = fopen("./dummy_file", "wb");
            if (file) {
                fwrite(Data, 1, Size, file);
                fclose(file);
                magic_compile(magic, "./dummy_file");
            }
        }
        magic_close(magic);
    }
}

static void fuzz_magic_check(const uint8_t *Data, size_t Size) {
    struct magic_set *magic = magic_open(0);
    if (magic) {
        if (Size > 0) {
            FILE *file = fopen("./dummy_file", "wb");
            if (file) {
                fwrite(Data, 1, Size, file);
                fclose(file);
                magic_check(magic, "./dummy_file");
            }
        }
        magic_close(magic);
    }
}

static void fuzz_magic_buffer(const uint8_t *Data, size_t Size) {
    magic_t magic = magic_open(0);
    if (magic) {
        magic_buffer(magic, Data, Size);
        magic_close(magic);
    }
}

static void fuzz_magic_list(const uint8_t *Data, size_t Size) {
    struct magic_set *magic = magic_open(0);
    if (magic) {
        if (Size > 0) {
            FILE *file = fopen("./dummy_file", "wb");
            if (file) {
                fwrite(Data, 1, Size, file);
                fclose(file);
                magic_list(magic, "./dummy_file");
            }
        }
        magic_close(magic);
    }
}

static void fuzz_magic_descriptor(const uint8_t *Data, size_t Size) {
    magic_t magic = magic_open(0);
    if (magic) {
        int fd = open("./dummy_file", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
        if (fd != -1) {
            write(fd, Data, Size);
            lseek(fd, 0, SEEK_SET);
            magic_descriptor(magic, fd);
            close(fd);
        }
        magic_close(magic);
    }
}

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    fuzz_magic_getpath(Data, Size);
    fuzz_magic_compile(Data, Size);
    fuzz_magic_check(Data, Size);
    fuzz_magic_buffer(Data, Size);
    fuzz_magic_list(Data, Size);
    fuzz_magic_descriptor(Data, Size);
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

        LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    