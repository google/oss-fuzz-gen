// This fuzz driver is generated for library file, aiming to fuzz the following functions:
// magic_open at magic.c:268:1 in magic.h
// magic_load at magic.c:318:1 in magic.h
// magic_descriptor at magic.c:404:1 in magic.h
// magic_file at magic.c:415:1 in magic.h
// magic_error at magic.c:570:1 in magic.h
// magic_open at magic.c:268:1 in magic.h
// magic_load at magic.c:318:1 in magic.h
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
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Step 1: Prepare the environment
    magic_t magic_cookie = magic_open(MAGIC_NONE);
    if (!magic_cookie) return 0;

    // Try to load a magic database (ensure null-termination)
    std::string filename_str;
    if (Size > 1) {
        size_t filename_len = strnlen(reinterpret_cast<const char*>(Data + 1), Size - 1);
        filename_str.assign(reinterpret_cast<const char*>(Data + 1), filename_len);
    }
    const char *filename = filename_str.empty() ? nullptr : filename_str.c_str();
    magic_load(magic_cookie, filename);

    // Step 2: Write data to a dummy file
    write_dummy_file(Data, Size);

    // Step 3: Open the dummy file and get its descriptor
    int fd = open("./dummy_file", O_RDONLY);
    if (fd != -1) {
        // Step 4: Call various functions to explore different states
        magic_descriptor(magic_cookie, fd);
        close(fd);
    }

    // Step 5: Use magic_file
    magic_file(magic_cookie, "./dummy_file");

    // Step 6: Check for errors
    magic_error(magic_cookie);

    // Step 7: Use magic_list with a new magic_set
    magic_t magic_list_cookie = magic_open(MAGIC_NONE);
    if (magic_list_cookie) {
        magic_load(magic_list_cookie, filename);
        magic_list(magic_list_cookie, filename);
        magic_close(magic_list_cookie);
    }

    // Step 8: Cleanup
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

        LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    