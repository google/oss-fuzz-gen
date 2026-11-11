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
// magic_load at magic.c:318:1 in magic.h
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
#include <iostream>
#include <fstream>

static void fuzz_magic_error(magic_t magic) {
    const char *error = magic_error(magic);
    if (error) {
        std::cerr << "magic_error: " << error << std::endl;
    }
}

static void fuzz_magic_getpath(const uint8_t *Data, size_t Size) {
    std::string path(reinterpret_cast<const char*>(Data), Size);
    const char *result = magic_getpath(path.c_str(), 0);
    if (result) {
        std::cerr << "magic_getpath: " << result << std::endl;
    }
}

static void fuzz_magic_file(magic_t magic, const uint8_t *Data, size_t Size) {
    std::ofstream dummy_file("./dummy_file");
    dummy_file.write(reinterpret_cast<const char*>(Data), Size);
    dummy_file.close();

    const char *result = magic_file(magic, "./dummy_file");
    if (result) {
        std::cerr << "magic_file: " << result << std::endl;
    }
}

static void fuzz_magic_check(const uint8_t *Data, size_t Size) {
    magic_t magic = magic_open(MAGIC_NONE);
    if (magic) {
        std::string path(reinterpret_cast<const char*>(Data), Size);
        int check_result = magic_check(magic, path.c_str());
        std::cerr << "magic_check: " << check_result << std::endl;
        magic_close(magic);
    }
}

static void fuzz_magic_buffer(magic_t magic, const uint8_t *Data, size_t Size) {
    const char *result = magic_buffer(magic, Data, Size);
    if (result) {
        std::cerr << "magic_buffer: " << result << std::endl;
    }
}

static void fuzz_magic_load(magic_t magic, const uint8_t *Data, size_t Size) {
    std::string path(reinterpret_cast<const char*>(Data), Size);
    int load_result = magic_load(magic, path.c_str());
    std::cerr << "magic_load: " << load_result << std::endl;
}

extern "C" int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size) {
    magic_t magic = magic_open(MAGIC_NONE);
    if (!magic) {
        return 0;
    }

    // Load default magic database to avoid use-after-free error
    if (magic_load(magic, nullptr) != 0) {
        magic_close(magic);
        return 0;
    }

    fuzz_magic_error(magic);
    fuzz_magic_getpath(Data, Size);
    fuzz_magic_file(magic, Data, Size);
    fuzz_magic_buffer(magic, Data, Size);
    fuzz_magic_load(magic, Data, Size);

    // Call magic_check with a separate magic instance
    fuzz_magic_check(Data, Size);

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

        LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    