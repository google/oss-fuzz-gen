// This fuzz driver is generated for library file, aiming to fuzz the following functions:
// magic_open at magic.c:268:1 in magic.h
// magic_load at magic.c:318:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
// magic_descriptor at magic.c:404:1 in magic.h
// magic_error at magic.c:570:1 in magic.h
// magic_file at magic.c:415:1 in magic.h
// magic_error at magic.c:570:1 in magic.h
// magic_open at magic.c:268:1 in magic.h
// magic_load at magic.c:318:1 in magic.h
// magic_list at magic.c:357:1 in magic.h
// magic_error at magic.c:570:1 in magic.h
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
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    // Prepare a dummy file for testing
    const char *dummy_file_path = "./dummy_file";
    int fd = open(dummy_file_path, O_CREAT | O_RDWR, 0666);
    if (fd == -1) {
        return 0;
    }
    if (write(fd, Data, Size) != Size) {
        close(fd);
        return 0;
    }
    lseek(fd, 0, SEEK_SET);

    // Open a magic cookie
    magic_t magic_cookie = magic_open(MAGIC_NONE);
    if (magic_cookie == NULL) {
        close(fd);
        return 0;
    }

    // Load the default magic database
    if (magic_load(magic_cookie, NULL) != 0) {
        magic_close(magic_cookie);
        close(fd);
        return 0;
    }

    // Test magic_descriptor
    const char *desc = magic_descriptor(magic_cookie, fd);
    if (desc == NULL) {
        const char *error = magic_error(magic_cookie);
        if (error) {
            std::cerr << "magic_descriptor error: " << error << std::endl;
        }
    }

    // Test magic_file
    desc = magic_file(magic_cookie, dummy_file_path);
    if (desc == NULL) {
        const char *error = magic_error(magic_cookie);
        if (error) {
            std::cerr << "magic_file error: " << error << std::endl;
        }
    }

    // Test magic_list with a new magic set
    magic_t magic_list_cookie = magic_open(MAGIC_NONE);
    if (magic_list_cookie != NULL) {
        if (magic_load(magic_list_cookie, NULL) == 0) {
            if (magic_list(magic_list_cookie, NULL) == -1) {
                const char *error = magic_error(magic_list_cookie);
                if (error) {
                    std::cerr << "magic_list error: " << error << std::endl;
                }
            }
        }
        magic_close(magic_list_cookie);
    }

    // Clean up
    magic_close(magic_cookie);
    close(fd);
    unlink(dummy_file_path);

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

        LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    