// This fuzz driver is generated for library file, aiming to fuzz the following functions:
// magic_open at magic.c:268:1 in magic.h
// magic_compile at magic.c:341:1 in magic.h
// magic_compile at magic.c:341:1 in magic.h
// magic_load at magic.c:318:1 in magic.h
// magic_load at magic.c:318:1 in magic.h
// magic_file at magic.c:415:1 in magic.h
// magic_buffer at magic.c:552:1 in magic.h
// magic_error at magic.c:570:1 in magic.h
// magic_open at magic.c:268:1 in magic.h
// magic_list at magic.c:357:1 in magic.h
// magic_list at magic.c:357:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
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
#include <cstring>
#include <cstdlib>
#include <cstdio>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    magic_t cookie = magic_open(MAGIC_NONE);
    if (!cookie) return 0;

    const char *magicfile = "./dummy_file";
    const char *cstr = reinterpret_cast<const char *>(Data);
    size_t cstr_size = strnlen(cstr, Size);

    // Fuzzing magic_compile
    if (cstr_size < Size) {
        magic_compile(cookie, cstr);
    } else {
        magic_compile(cookie, magicfile);
    }

    // Fuzzing magic_load
    if (cstr_size < Size) {
        magic_load(cookie, cstr);
    } else {
        magic_load(cookie, magicfile);
    }

    // Fuzzing magic_file
    write_dummy_file(Data, Size);
    magic_file(cookie, magicfile);

    // Fuzzing magic_buffer
    magic_buffer(cookie, Data, Size);

    // Fuzzing magic_error
    magic_error(cookie);

    // Fuzzing magic_list with a new magic_set
    magic_t list_cookie = magic_open(MAGIC_NONE);
    if (list_cookie) {
        if (cstr_size < Size) {
            magic_list(list_cookie, cstr);
        } else {
            magic_list(list_cookie, magicfile);
        }
        magic_close(list_cookie);
    }

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

        LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    