// This fuzz driver is generated for library file, aiming to fuzz the following functions:
// magic_open at magic.c:268:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
// magic_descriptor at magic.c:404:1 in magic.h
// magic_error at magic.c:570:1 in magic.h
// magic_open at magic.c:268:1 in magic.h
// magic_check at magic.c:349:1 in magic.h
// magic_error at magic.c:570:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
// magic_open at magic.c:268:1 in magic.h
// magic_list at magic.c:357:1 in magic.h
// magic_error at magic.c:570:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
// magic_file at magic.c:415:1 in magic.h
// magic_error at magic.c:570:1 in magic.h
// magic_open at magic.c:268:1 in magic.h
// magic_compile at magic.c:341:1 in magic.h
// magic_error at magic.c:570:1 in magic.h
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
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>
#include <cstdlib>

static void fuzz_magic_descriptor(magic_t magic, const uint8_t *Data, size_t Size) {
    int fd = open("./dummy_file", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd != -1) {
        write(fd, Data, Size);
        lseek(fd, 0, SEEK_SET);
        const char *result = magic_descriptor(magic, fd);
        if (result == nullptr) {
            magic_error(magic);
        }
        close(fd);
    }
}

static void fuzz_magic_check(const uint8_t *Data, size_t Size) {
    magic_t magic = magic_open(MAGIC_NONE);
    if (magic) {
        char filename[] = "./dummy_file";
        FILE *file = fopen(filename, "wb");
        if (file) {
            fwrite(Data, 1, Size, file);
            fclose(file);
            int result = magic_check(magic, filename);
            if (result == -1) {
                magic_error(magic);
            }
            remove(filename);
        }
        magic_close(magic);
    }
}

static void fuzz_magic_list(const uint8_t *Data, size_t Size) {
    magic_t magic = magic_open(MAGIC_NONE);
    if (magic) {
        char filename[] = "./dummy_file";
        FILE *file = fopen(filename, "wb");
        if (file) {
            fwrite(Data, 1, Size, file);
            fclose(file);
            int result = magic_list(magic, filename);
            if (result == -1) {
                magic_error(magic);
            }
            remove(filename);
        }
        magic_close(magic);
    }
}

static void fuzz_magic_file(magic_t magic, const uint8_t *Data, size_t Size) {
    char filename[] = "./dummy_file";
    FILE *file = fopen(filename, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
        const char *result = magic_file(magic, filename);
        if (result == nullptr) {
            magic_error(magic);
        }
        remove(filename);
    }
}

static void fuzz_magic_compile(const uint8_t *Data, size_t Size) {
    magic_t magic = magic_open(MAGIC_NONE);
    if (magic) {
        char filename[] = "./dummy_file";
        FILE *file = fopen(filename, "wb");
        if (file) {
            fwrite(Data, 1, Size, file);
            fclose(file);
            int result = magic_compile(magic, filename);
            if (result == -1) {
                magic_error(magic);
            }
            remove(filename);
        }
        magic_close(magic);
    }
}

extern "C" int LLVMFuzzerTestOneInput_41(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    magic_t magic = magic_open(MAGIC_NONE);
    if (magic) {
        fuzz_magic_descriptor(magic, Data, Size);
        fuzz_magic_file(magic, Data, Size);
        magic_close(magic);
    }

    fuzz_magic_check(Data, Size);
    fuzz_magic_list(Data, Size);
    fuzz_magic_compile(Data, Size);

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

        LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    