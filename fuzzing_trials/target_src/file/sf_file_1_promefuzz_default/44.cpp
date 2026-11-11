// This fuzz driver is generated for library file, aiming to fuzz the following functions:
// magic_close at magic.c:307:1 in magic.h
// magic_buffer at magic.c:552:1 in magic.h
// magic_descriptor at magic.c:404:1 in magic.h
// magic_open at magic.c:268:1 in magic.h
// magic_load at magic.c:318:1 in magic.h
// magic_check at magic.c:349:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
// magic_open at magic.c:268:1 in magic.h
// magic_load at magic.c:318:1 in magic.h
// magic_list at magic.c:357:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
// magic_file at magic.c:415:1 in magic.h
// magic_open at magic.c:268:1 in magic.h
// magic_load at magic.c:318:1 in magic.h
// magic_compile at magic.c:341:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
// magic_open at magic.c:268:1 in magic.h
// magic_load at magic.c:318:1 in magic.h
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
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>

static void fuzz_magic_buffer(magic_t magic, const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        const char *result = magic_buffer(magic, Data, Size);
        if (result != nullptr) {
            std::cout << "magic_buffer: " << result << std::endl;
        }
    }
}

static void fuzz_magic_descriptor(magic_t magic, const uint8_t *Data, size_t Size) {
    int fd = open("./dummy_file", O_RDWR | O_CREAT, S_IRWXU);
    if (fd != -1) {
        write(fd, Data, Size);
        lseek(fd, 0, SEEK_SET);
        const char *result = magic_descriptor(magic, fd);
        if (result != nullptr) {
            std::cout << "magic_descriptor: " << result << std::endl;
        }
        close(fd);
    }
}

static void fuzz_magic_check(const uint8_t *Data, size_t Size) {
    magic_t magic = magic_open(MAGIC_NONE);
    if (magic) {
        magic_load(magic, nullptr);
        const char *filename = "./dummy_file";
        int fd = open(filename, O_RDWR | O_CREAT, S_IRWXU);
        if (fd != -1) {
            write(fd, Data, Size);
            close(fd);
            magic_check(magic, filename);
        }
        magic_close(magic);
    }
}

static void fuzz_magic_list(const uint8_t *Data, size_t Size) {
    magic_t magic = magic_open(MAGIC_NONE);
    if (magic) {
        magic_load(magic, nullptr);
        int result = magic_list(magic, nullptr);
        if (result != -1) {
            std::cout << "magic_list: success" << std::endl;
        }
        magic_close(magic);
    }
}

static void fuzz_magic_file(magic_t magic, const uint8_t *Data, size_t Size) {
    const char *filename = "./dummy_file";
    int fd = open(filename, O_RDWR | O_CREAT, S_IRWXU);
    if (fd != -1) {
        write(fd, Data, Size);
        close(fd);
        const char *result = magic_file(magic, filename);
        if (result != nullptr) {
            std::cout << "magic_file: " << result << std::endl;
        }
    }
}

static void fuzz_magic_compile(const uint8_t *Data, size_t Size) {
    magic_t magic = magic_open(MAGIC_NONE);
    if (magic) {
        magic_load(magic, nullptr);
        const char *filename = "./dummy_file";
        int fd = open(filename, O_RDWR | O_CREAT, S_IRWXU);
        if (fd != -1) {
            write(fd, Data, Size);
            close(fd);
            magic_compile(magic, filename);
        }
        magic_close(magic);
    }
}

extern "C" int LLVMFuzzerTestOneInput_44(const uint8_t *Data, size_t Size) {
    magic_t magic = magic_open(MAGIC_NONE);
    if (magic) {
        magic_load(magic, nullptr);
        fuzz_magic_buffer(magic, Data, Size);
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

        LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    