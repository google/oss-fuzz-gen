// This fuzz driver is generated for library file, aiming to fuzz the following functions:
// magic_open at magic.c:268:1 in magic.h
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
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    magic_t magic_cookie = magic_open(MAGIC_NONE);
    if (magic_cookie == NULL) return 0;

    // Fuzz magic_buffer
    const char *buffer_result = magic_buffer(magic_cookie, Data, Size);
    if (buffer_result == NULL) {
        const char *error = magic_error(magic_cookie);
        if (error) {
            // Handle error
        }
    }

    // Fuzz magic_descriptor
    int fd = open("./dummy_file", O_CREAT | O_RDWR, 0644);
    if (fd != -1) {
        write(fd, Data, Size);
        lseek(fd, 0, SEEK_SET);
        const char *descriptor_result = magic_descriptor(magic_cookie, fd);
        if (descriptor_result == NULL) {
            const char *error = magic_error(magic_cookie);
            if (error) {
                // Handle error
            }
        }
        close(fd);
    }

    // Fuzz magic_check
    magic_t check_cookie = magic_open(MAGIC_NONE);
    if (check_cookie != NULL) {
        int check_result = magic_check(check_cookie, NULL);
        if (check_result == -1) {
            const char *error = magic_error(check_cookie);
            if (error) {
                // Handle error
            }
        }
        magic_close(check_cookie);
    }

    // Fuzz magic_list
    magic_t list_cookie = magic_open(MAGIC_NONE);
    if (list_cookie != NULL) {
        int list_result = magic_list(list_cookie, NULL);
        if (list_result == -1) {
            const char *error = magic_error(list_cookie);
            if (error) {
                // Handle error
            }
        }
        magic_close(list_cookie);
    }

    // Fuzz magic_file
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
        const char *file_result = magic_file(magic_cookie, "./dummy_file");
        if (file_result == NULL) {
            const char *error = magic_error(magic_cookie);
            if (error) {
                // Handle error
            }
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

        LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    