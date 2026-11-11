// This fuzz driver is generated for library file, aiming to fuzz the following functions:
// magic_open at magic.c:267:1 in magic.h
// magic_load_buffers at magic.c:329:1 in magic.h
// magic_list at magic.c:356:1 in magic.h
// magic_buffer at magic.c:551:1 in magic.h
// magic_getparam at magic.c:656:1 in magic.h
// magic_compile at magic.c:340:1 in magic.h
// magic_errno at magic.c:577:1 in magic.h
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

extern "C" int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Initialize magic set
    magic_t magic = magic_open(MAGIC_NONE);
    if (magic == nullptr) {
        return 0;
    }

    // Fuzz magic_load_buffers
    void *buffers[] = {reinterpret_cast<void *>(const_cast<uint8_t *>(Data))};
    size_t buffer_sizes[] = {Size};
    int load_result = magic_load_buffers(magic, buffers, buffer_sizes, 1);

    if (load_result == 0) {
        // Fuzz magic_list only if magic_load_buffers succeeds
        char *db_files = (Size > 1) ? reinterpret_cast<char *>(malloc(Size)) : nullptr;
        if (db_files) {
            memcpy(db_files, Data, Size - 1);
            db_files[Size - 1] = '\0'; // Ensure null-termination
            magic_list(magic, db_files);
            free(db_files);
        }

        // Fuzz magic_buffer
        const char *description = magic_buffer(magic, Data, Size);
        if (description) {
            std::cout << "Description: " << description << std::endl;
        }

        // Fuzz magic_getparam
        int param = MAGIC_PARAM_INDIR_MAX;
        size_t val;
        magic_getparam(magic, param, &val);

        // Fuzz magic_compile
        magic_compile(magic, nullptr);
    }

    // Fuzz magic_errno
    int err = magic_errno(magic);
    std::cout << "Error code: " << err << std::endl;

    // Cleanup
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

        LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    