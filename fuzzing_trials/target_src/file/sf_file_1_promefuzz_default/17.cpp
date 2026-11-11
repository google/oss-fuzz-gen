// This fuzz driver is generated for library file, aiming to fuzz the following functions:
// magic_open at magic.c:268:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
// magic_buffer at magic.c:552:1 in magic.h
// magic_descriptor at magic.c:404:1 in magic.h
// magic_check at magic.c:349:1 in magic.h
// magic_list at magic.c:357:1 in magic.h
// magic_file at magic.c:415:1 in magic.h
// magic_compile at magic.c:341:1 in magic.h
// magic_open at magic.c:268:1 in magic.h
// magic_load at magic.c:318:1 in magic.h
// magic_open at magic.c:268:1 in magic.h
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
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>

static void fuzz_magic_buffer(magic_t cookie, const uint8_t *Data, size_t Size) {
    if (cookie) {
        magic_buffer(cookie, Data, Size);
    }
}

static void fuzz_magic_descriptor(magic_t cookie, const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        int fd = open("./dummy_file", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
        if (fd != -1) {
            write(fd, Data, Size);
            lseek(fd, 0, SEEK_SET);
            magic_descriptor(cookie, fd);
            close(fd);
        }
    }
}

static void fuzz_magic_check(magic_t cookie, const uint8_t *Data, size_t Size) {
    char filename[256];
    snprintf(filename, sizeof(filename), "./dummy_file_%zu", Size);
    FILE *file = fopen(filename, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
        magic_check(cookie, filename);
    }
    remove(filename);
}

static void fuzz_magic_list(magic_t cookie, const uint8_t *Data, size_t Size) {
    char filename[256];
    snprintf(filename, sizeof(filename), "./dummy_file_%zu", Size);
    FILE *file = fopen(filename, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
        magic_list(cookie, filename);
    }
    remove(filename);
}

static void fuzz_magic_file(magic_t cookie, const uint8_t *Data, size_t Size) {
    char filename[256];
    snprintf(filename, sizeof(filename), "./dummy_file_%zu", Size);
    FILE *file = fopen(filename, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
        magic_file(cookie, filename);
    }
    remove(filename);
}

static void fuzz_magic_compile(magic_t cookie, const uint8_t *Data, size_t Size) {
    char filename[256];
    snprintf(filename, sizeof(filename), "./dummy_file_%zu", Size);
    FILE *file = fopen(filename, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
        magic_compile(cookie, filename);
    }
    remove(filename);
}

extern "C" int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    magic_t cookie = magic_open(MAGIC_NONE);
    if (!cookie) {
        return 0;
    }

    magic_load(cookie, NULL);

    fuzz_magic_buffer(cookie, Data, Size);
    fuzz_magic_descriptor(cookie, Data, Size);

    magic_t check_cookie = magic_open(MAGIC_NONE);
    if (check_cookie) {
        fuzz_magic_check(check_cookie, Data, Size);
        magic_close(check_cookie);
    }

    magic_t list_cookie = magic_open(MAGIC_NONE);
    if (list_cookie) {
        fuzz_magic_list(list_cookie, Data, Size);
        magic_close(list_cookie);
    }

    fuzz_magic_file(cookie, Data, Size);
    fuzz_magic_compile(cookie, Data, Size);

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

        LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    