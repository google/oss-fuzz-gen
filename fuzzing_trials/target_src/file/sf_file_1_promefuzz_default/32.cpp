// This fuzz driver is generated for library file, aiming to fuzz the following functions:
// magic_open at magic.c:268:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
// magic_errno at magic.c:578:1 in magic.h
// magic_descriptor at magic.c:404:1 in magic.h
// magic_load at magic.c:318:1 in magic.h
// magic_setflags at magic.c:595:1 in magic.h
// magic_open at magic.c:268:1 in magic.h
// magic_load at magic.c:318:1 in magic.h
// magic_list at magic.c:357:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
// magic_load at magic.c:318:1 in magic.h
// magic_compile at magic.c:341:1 in magic.h
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
#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstring>

static void fuzz_magic_errno(magic_t magic) {
    int err = magic_errno(magic);
    (void)err; // Suppress unused variable warning
}

static void fuzz_magic_descriptor(magic_t magic, const uint8_t *Data, size_t Size) {
    int fd = open("./dummy_file", O_RDWR | O_CREAT, 0666);
    if (fd < 0) return;

    write(fd, Data, Size);
    lseek(fd, 0, SEEK_SET);

    const char *desc = magic_descriptor(magic, fd);
    (void)desc; // Suppress unused variable warning

    close(fd);
}

static void fuzz_magic_load(magic_t magic, const uint8_t *Data, size_t Size) {
    char filename[256];
    snprintf(filename, sizeof(filename), "./dummy_file_%zu", Size);
    FILE *file = fopen(filename, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);

        int result = magic_load(magic, filename);
        (void)result; // Suppress unused variable warning

        remove(filename);
    }
}

static void fuzz_magic_setflags(magic_t magic, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return;

    int flags;
    memcpy(&flags, Data, sizeof(int));

    int result = magic_setflags(magic, flags);
    (void)result; // Suppress unused variable warning
}

static void fuzz_magic_list(const uint8_t *Data, size_t Size) {
    magic_t magic = magic_open(MAGIC_NONE);
    if (!magic) return;

    char filename[256];
    snprintf(filename, sizeof(filename), "./dummy_file_%zu", Size);
    FILE *file = fopen(filename, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);

        magic_load(magic, filename);

        int result = magic_list(magic, filename);
        (void)result; // Suppress unused variable warning

        remove(filename);
    }

    magic_close(magic);
}

static void fuzz_magic_compile(magic_t magic, const uint8_t *Data, size_t Size) {
    char filename[256];
    snprintf(filename, sizeof(filename), "./dummy_file_%zu", Size);
    FILE *file = fopen(filename, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);

        magic_load(magic, filename);

        int result = magic_compile(magic, filename);
        (void)result; // Suppress unused variable warning

        remove(filename);
    }
}

extern "C" int LLVMFuzzerTestOneInput_32(const uint8_t *Data, size_t Size) {
    magic_t magic = magic_open(MAGIC_NONE);
    if (!magic) return 0;

    fuzz_magic_errno(magic);
    fuzz_magic_descriptor(magic, Data, Size);
    fuzz_magic_load(magic, Data, Size);
    fuzz_magic_setflags(magic, Data, Size);
    fuzz_magic_compile(magic, Data, Size);
    fuzz_magic_list(Data, Size);

    magic_close(magic);
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

        LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    