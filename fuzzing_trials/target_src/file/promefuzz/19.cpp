// This fuzz driver is generated for library file, aiming to fuzz the following functions:
// magic_open at magic.c:267:1 in magic.h
// magic_load at magic.c:317:1 in magic.h
// magic_close at magic.c:306:1 in magic.h
// magic_file at magic.c:414:1 in magic.h
// magic_errno at magic.c:577:1 in magic.h
// magic_error at magic.c:569:1 in magic.h
// magic_buffer at magic.c:551:1 in magic.h
// magic_errno at magic.c:577:1 in magic.h
// magic_error at magic.c:569:1 in magic.h
// magic_compile at magic.c:340:1 in magic.h
// magic_errno at magic.c:577:1 in magic.h
// magic_error at magic.c:569:1 in magic.h
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
#include <cstddef>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>

static void WriteDummyFile(const uint8_t *Data, size_t Size) {
    std::ofstream ofs("./dummy_file", std::ios::binary);
    if (ofs.is_open()) {
        ofs.write(reinterpret_cast<const char*>(Data), Size);
        ofs.close();
    }
}

extern "C" int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    magic_t magic_cookie = magic_open(MAGIC_NONE);
    if (magic_cookie == NULL) {
        return 0;
    }

    if (magic_load(magic_cookie, NULL) == -1) {
        magic_close(magic_cookie);
        return 0;
    }

    // Fuzz magic_file
    WriteDummyFile(Data, Size);
    const char *file_result = magic_file(magic_cookie, "./dummy_file");
    if (file_result == NULL) {
        int err = magic_errno(magic_cookie);
        const char *err_str = magic_error(magic_cookie);
        if (err_str) {
            std::cerr << "magic_file error: " << err_str << " (errno: " << err << ")" << std::endl;
        }
    }

    // Fuzz magic_buffer
    const char *buffer_result = magic_buffer(magic_cookie, Data, Size);
    if (buffer_result == NULL) {
        int err = magic_errno(magic_cookie);
        const char *err_str = magic_error(magic_cookie);
        if (err_str) {
            std::cerr << "magic_buffer error: " << err_str << " (errno: " << err << ")" << std::endl;
        }
    }

    // Fuzz magic_compile
    if (magic_compile(magic_cookie, NULL) == -1) {
        int err = magic_errno(magic_cookie);
        const char *err_str = magic_error(magic_cookie);
        if (err_str) {
            std::cerr << "magic_compile error: " << err_str << " (errno: " << err << ")" << std::endl;
        }
    }

    magic_close(magic_cookie);
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

        LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    