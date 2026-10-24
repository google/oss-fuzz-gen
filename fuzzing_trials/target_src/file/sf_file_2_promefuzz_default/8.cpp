// This fuzz driver is generated for library file, aiming to fuzz the following functions:
// magic_open at magic.c:268:1 in magic.h
// magic_load at magic.c:318:1 in magic.h
// magic_close at magic.c:307:1 in magic.h
// magic_file at magic.c:415:1 in magic.h
// magic_error at magic.c:570:1 in magic.h
// magic_buffer at magic.c:552:1 in magic.h
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
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <magic.h>

static void writeDummyFile(const uint8_t *Data, size_t Size) {
    std::ofstream outFile("./dummy_file", std::ios::binary);
    if (outFile.is_open()) {
        outFile.write(reinterpret_cast<const char *>(Data), Size);
        outFile.close();
    }
}

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Open a magic cookie
    magic_t magicCookie = magic_open(MAGIC_NONE);
    if (magicCookie == nullptr) {
        return 0;
    }

    // Load the default magic database
    if (magic_load(magicCookie, nullptr) != 0) {
        magic_close(magicCookie);
        return 0;
    }

    // Test magic_file
    writeDummyFile(Data, Size);
    const char *fileResult = magic_file(magicCookie, "./dummy_file");
    if (fileResult == nullptr) {
        const char *error = magic_error(magicCookie);
        if (error) {
            std::cerr << "magic_file error: " << error << std::endl;
        }
    }

    // Test magic_buffer
    const char *bufferResult = magic_buffer(magicCookie, Data, Size);
    if (bufferResult == nullptr) {
        const char *error = magic_error(magicCookie);
        if (error) {
            std::cerr << "magic_buffer error: " << error << std::endl;
        }
    }

    // Close the magic cookie
    magic_close(magicCookie);

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
    