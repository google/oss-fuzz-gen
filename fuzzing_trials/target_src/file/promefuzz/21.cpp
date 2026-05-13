// This fuzz driver is generated for library file, aiming to fuzz the following functions:
// magic_open at magic.c:267:1 in magic.h
// magic_list at magic.c:356:1 in magic.h
// magic_version at magic.c:607:1 in magic.h
// magic_load_buffers at magic.c:329:1 in magic.h
// magic_getparam at magic.c:656:1 in magic.h
// magic_errno at magic.c:577:1 in magic.h
// magic_compile at magic.c:340:1 in magic.h
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
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <iostream>
#include <fstream>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    std::ofstream outfile("./dummy_file", std::ios::binary);
    outfile.write(reinterpret_cast<const char*>(Data), Size);
    outfile.close();
}

extern "C" int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Initialize a new magic set
    magic_t magic = magic_open(MAGIC_NONE);
    if (magic == nullptr) {
        return 0;
    }

    // Write data to a dummy file
    write_dummy_file(Data, Size);

    // Fuzz magic_list
    const char *dummyPath = "./dummy_file";
    magic_list(magic, dummyPath);

    // Fuzz magic_version
    int version = magic_version();
    (void)version; // Suppress unused variable warning

    // Prepare buffer for magic_load_buffers
    void *buffers[1] = { const_cast<uint8_t*>(Data) };
    size_t buffer_sizes[1] = { Size };
    magic_load_buffers(magic, buffers, buffer_sizes, 1);

    // Fuzz magic_getparam
    int param = MAGIC_PARAM_INDIR_MAX;
    int64_t val;
    magic_getparam(magic, param, &val);

    // Fuzz magic_errno
    int err = magic_errno(magic);
    (void)err; // Suppress unused variable warning

    // Fuzz magic_compile
    magic_compile(magic, dummyPath);

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

        LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    