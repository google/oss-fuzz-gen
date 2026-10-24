// This fuzz driver is generated for library file, aiming to fuzz the following functions:
// magic_error at magic.c:570:1 in magic.h
// magic_getpath at magic.c:255:1 in magic.h
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
#include <cstddef>
#include <cstring>
#include <fstream>

static void fuzz_magic_error(magic_t magic) {
    magic_error(magic);
}

static void fuzz_magic_getpath(const uint8_t *Data, size_t Size) {
    std::string path(reinterpret_cast<const char *>(Data), Size);
    magic_getpath(path.c_str(), 0);
    magic_getpath(path.c_str(), 1);
}

static void fuzz_magic_file(magic_t magic, const uint8_t *Data, size_t Size) {
    std::ofstream file("./dummy_file");
    if (file.is_open()) {
        file.write(reinterpret_cast<const char *>(Data), Size);
        file.close();
        magic_file(magic, "./dummy_file");
    }
}

static void fuzz_magic_check(const uint8_t *Data, size_t Size) {
    struct magic_set *magic = magic_open(0);
    if (magic) {
        std::string path(reinterpret_cast<const char *>(Data), Size);
        magic_check(magic, path.c_str());
        magic_close(magic);
    }
}

static void fuzz_magic_buffer(magic_t magic, const uint8_t *Data, size_t Size) {
    magic_buffer(magic, Data, Size);
}

static void fuzz_magic_load(magic_t magic, const uint8_t *Data, size_t Size) {
    std::string path(reinterpret_cast<const char *>(Data), Size);
    magic_load(magic, path.c_str());
}

extern "C" int LLVMFuzzerTestOneInput_46(const uint8_t *Data, size_t Size) {
    magic_t magic = magic_open(MAGIC_NONE);
    if (magic) {
        fuzz_magic_error(magic);
        fuzz_magic_getpath(Data, Size);
        fuzz_magic_file(magic, Data, Size);
        fuzz_magic_check(Data, Size);
        fuzz_magic_buffer(magic, Data, Size);
        fuzz_magic_load(magic, Data, Size);
        magic_close(magic);
    }
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

        LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    