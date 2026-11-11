// This fuzz driver is generated for library file, aiming to fuzz the following functions:
// magic_open at magic.c:268:1 in magic.h
// magic_open at magic.c:268:1 in magic.h
// magic_open at magic.c:268:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
// magic_buffer at magic.c:552:1 in magic.h
// magic_descriptor at magic.c:404:1 in magic.h
// magic_check at magic.c:349:1 in magic.h
// magic_list at magic.c:357:1 in magic.h
// magic_file at magic.c:415:1 in magic.h
// magic_compile at magic.c:341:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
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
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput_49(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a magic cookie for functions
    magic_t magic_cookie = magic_open(MAGIC_NONE);
    if (magic_cookie == NULL) return 0;

    // Create a separate magic set for magic_check and magic_list
    magic_t magic_check_set = magic_open(MAGIC_NONE);
    magic_t magic_list_set = magic_open(MAGIC_NONE);
    if (magic_check_set == NULL || magic_list_set == NULL) {
        magic_close(magic_cookie);
        if (magic_check_set) magic_close(magic_check_set);
        if (magic_list_set) magic_close(magic_list_set);
        return 0;
    }

    // Prepare a dummy file
    const char *dummy_file = "./dummy_file";
    int fd = open(dummy_file, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        magic_close(magic_cookie);
        magic_close(magic_check_set);
        magic_close(magic_list_set);
        return 0;
    }
    write(fd, Data, Size);
    lseek(fd, 0, SEEK_SET);

    // Test magic_buffer
    magic_buffer(magic_cookie, Data, Size);

    // Test magic_descriptor
    magic_descriptor(magic_cookie, fd);

    // Test magic_check
    magic_check(magic_check_set, dummy_file);

    // Test magic_list
    magic_list(magic_list_set, dummy_file);

    // Test magic_file
    magic_file(magic_cookie, dummy_file);

    // Test magic_compile
    magic_compile(magic_cookie, dummy_file);

    // Cleanup
    close(fd);
    magic_close(magic_cookie);
    magic_close(magic_check_set);
    magic_close(magic_list_set);
    unlink(dummy_file);

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

        LLVMFuzzerTestOneInput_49(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    