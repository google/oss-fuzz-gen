// This fuzz driver is generated for library file, aiming to fuzz the following functions:
// magic_close at magic.c:307:1 in magic.h
// magic_buffer at magic.c:552:1 in magic.h
// magic_error at magic.c:570:1 in magic.h
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
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>

static void fuzz_magic_buffer(magic_t cookie, const uint8_t *Data, size_t Size) {
    const char *result = magic_buffer(cookie, Data, Size);
    if (result == NULL) {
        const char *error = magic_error(cookie);
        if (error) {
            fprintf(stderr, "magic_buffer error: %s\n", error);
        }
    }
}

static void fuzz_magic_descriptor(magic_t cookie) {
    int fd = open("./dummy_file", O_RDONLY);
    if (fd != -1) {
        const char *result = magic_descriptor(cookie, fd);
        if (result == NULL) {
            const char *error = magic_error(cookie);
            if (error) {
                fprintf(stderr, "magic_descriptor error: %s\n", error);
            }
        }
        close(fd);
    }
}

static void fuzz_magic_check(const uint8_t *Data, size_t Size) {
    magic_t cookie = magic_open(MAGIC_NONE);
    if (cookie) {
        FILE *dummy_file = fopen("./dummy_file", "wb");
        if (dummy_file) {
            fwrite(Data, 1, Size, dummy_file);
            fclose(dummy_file);
            int result = magic_check(cookie, "./dummy_file");
            if (result == -1) {
                const char *error = magic_error(cookie);
                if (error) {
                    fprintf(stderr, "magic_check error: %s\n", error);
                }
            }
        }
        magic_close(cookie);
    }
}

static void fuzz_magic_list(const uint8_t *Data, size_t Size) {
    magic_t cookie = magic_open(MAGIC_NONE);
    if (cookie) {
        FILE *dummy_file = fopen("./dummy_file", "wb");
        if (dummy_file) {
            fwrite(Data, 1, Size, dummy_file);
            fclose(dummy_file);
            int result = magic_list(cookie, "./dummy_file");
            if (result == -1) {
                const char *error = magic_error(cookie);
                if (error) {
                    fprintf(stderr, "magic_list error: %s\n", error);
                }
            }
        }
        magic_close(cookie);
    }
}

static void fuzz_magic_file(magic_t cookie) {
    FILE *dummy_file = fopen("./dummy_file", "w");
    if (dummy_file) {
        fprintf(dummy_file, "dummy data");
        fclose(dummy_file);
        const char *result = magic_file(cookie, "./dummy_file");
        if (result == NULL) {
            const char *error = magic_error(cookie);
            if (error) {
                fprintf(stderr, "magic_file error: %s\n", error);
            }
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    magic_t cookie = magic_open(MAGIC_NONE);
    if (cookie) {
        fuzz_magic_buffer(cookie, Data, Size);
        fuzz_magic_descriptor(cookie);
        fuzz_magic_file(cookie);
        magic_close(cookie);
    }

    fuzz_magic_check(Data, Size);
    fuzz_magic_list(Data, Size);

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

        LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    