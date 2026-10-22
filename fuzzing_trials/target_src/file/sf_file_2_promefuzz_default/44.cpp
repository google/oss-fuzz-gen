// This fuzz driver is generated for library file, aiming to fuzz the following functions:
// magic_error at magic.c:570:1 in magic.h
// magic_getpath at magic.c:255:1 in magic.h
// magic_file at magic.c:415:1 in magic.h
// magic_open at magic.c:268:1 in magic.h
// magic_check at magic.c:349:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
// magic_buffer at magic.c:552:1 in magic.h
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
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <exception>

static void handle_magic_error(magic_t magic) {
    const char *error = magic_error(magic);
    if (error) {
        fprintf(stderr, "Magic error: %s\n", error);
    }
}

static void fuzz_magic_getpath(const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        char *path = new char[Size + 1];
        memcpy(path, Data, Size);
        path[Size] = '\0';
        magic_getpath(path, 0);
        delete[] path;
    }
}

static void fuzz_magic_file(magic_t magic, const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
        magic_file(magic, "./dummy_file");
    }
}

static void fuzz_magic_check(const uint8_t *Data, size_t Size) {
    magic_t magic = magic_open(0);
    if (magic) {
        if (Size > 0) {
            char *path = new char[Size + 1];
            memcpy(path, Data, Size);
            path[Size] = '\0';
            magic_check(magic, path);
            delete[] path;
        }
        magic_close(magic);
    }
}

static void fuzz_magic_buffer(magic_t magic, const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        magic_buffer(magic, Data, Size);
    }
}

static void fuzz_magic_load(magic_t magic, const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        char *path = new char[Size + 1];
        memcpy(path, Data, Size);
        path[Size] = '\0';
        magic_load(magic, path);
        delete[] path;
    }
}

extern "C" int LLVMFuzzerTestOneInput_44(const uint8_t *Data, size_t Size) {
    magic_t magic = magic_open(MAGIC_NONE);
    if (!magic) {
        return 0;
    }

    try {
        handle_magic_error(magic);
        fuzz_magic_getpath(Data, Size);
        fuzz_magic_file(magic, Data, Size);
        fuzz_magic_check(Data, Size);
        fuzz_magic_buffer(magic, Data, Size);
        fuzz_magic_load(magic, Data, Size);
    } catch (const std::exception &e) {
        fprintf(stderr, "Exception: %s\n", e.what());
    }

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

        LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    