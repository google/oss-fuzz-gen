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
#include <cstdint>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>

static void fuzz_magic_buffer(magic_t cookie, const uint8_t *Data, size_t Size) {
    const char *result = magic_buffer(cookie, Data, Size);
    if (result) {
        // Process result if needed
    }
}

static void fuzz_magic_descriptor(magic_t cookie, const uint8_t *Data, size_t Size) {
    int fd = open("./dummy_file", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd != -1) {
        write(fd, Data, Size);
        lseek(fd, 0, SEEK_SET);
        const char *result = magic_descriptor(cookie, fd);
        if (result) {
            // Process result if needed
        }
        close(fd);
    }
}

static void fuzz_magic_check(const uint8_t *Data, size_t Size) {
    magic_t cookie = magic_open(MAGIC_NONE);
    if (cookie) {
        magic_load(cookie, NULL);
        char filename[] = "./dummy_file";
        FILE *file = fopen(filename, "wb");
        if (file) {
            fwrite(Data, 1, Size, file);
            fclose(file);
            magic_check(cookie, filename);
        }
        magic_close(cookie);
    }
}

static void fuzz_magic_list(const uint8_t *Data, size_t Size) {
    magic_t cookie = magic_open(MAGIC_NONE);
    if (cookie) {
        magic_load(cookie, NULL);
        char filename[] = "./dummy_file";
        FILE *file = fopen(filename, "wb");
        if (file) {
            fwrite(Data, 1, Size, file);
            fclose(file);
            magic_list(cookie, filename);
        }
        magic_close(cookie);
    }
}

static void fuzz_magic_file(magic_t cookie, const uint8_t *Data, size_t Size) {
    char filename[] = "./dummy_file";
    FILE *file = fopen(filename, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
        const char *result = magic_file(cookie, filename);
        if (result) {
            // Process result if needed
        }
    }
}

static void fuzz_magic_compile(const uint8_t *Data, size_t Size) {
    magic_t cookie = magic_open(MAGIC_NONE);
    if (cookie) {
        magic_load(cookie, NULL);
        char filename[] = "./dummy_file";
        FILE *file = fopen(filename, "wb");
        if (file) {
            fwrite(Data, 1, Size, file);
            fclose(file);
            magic_compile(cookie, filename);
        }
        magic_close(cookie);
    }
}

extern "C" int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size) {
    magic_t cookie = magic_open(MAGIC_NONE);
    if (!cookie) return 0;
    magic_load(cookie, NULL);

    fuzz_magic_buffer(cookie, Data, Size);
    fuzz_magic_descriptor(cookie, Data, Size);
    fuzz_magic_file(cookie, Data, Size);

    fuzz_magic_check(Data, Size);
    fuzz_magic_list(Data, Size);
    fuzz_magic_compile(Data, Size);

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

        LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    