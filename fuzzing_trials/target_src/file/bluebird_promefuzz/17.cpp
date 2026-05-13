#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include "magic.h"
#include <fstream>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    std::ofstream ofs("./dummy_file", std::ios::binary);
    ofs.write(reinterpret_cast<const char *>(Data), Size);
}

extern "C" int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize magic cookie
    magic_t magic_cookie = magic_open(MAGIC_NONE);
    if (!magic_cookie) {
        return 0;
    }

    // Prepare parameters
    int param = Data[0];
    size_t value_size = sizeof(size_t);
    if (Size < value_size + 1) {
        magic_close(magic_cookie);
        return 0;
    }
    const void *value = static_cast<const void *>(&Data[1]);

    // Test magic_setparam with proper size
    magic_setparam(magic_cookie, param, value);

    // Prepare buffers for magic_load_buffers
    void *buffers[1] = {const_cast<uint8_t *>(Data)};
    size_t buffer_sizes[1] = {Size};

    // Test magic_load_buffers
    magic_load_buffers(magic_cookie, buffers, buffer_sizes, 1);

    // Test magic_getparam with proper size
    void *get_value = malloc(value_size);
    if (get_value) {
        magic_getparam(magic_cookie, param, get_value);
        free(get_value);
    }

    // Test magic_errno
    magic_errno(magic_cookie);

    // Write dummy file for magic_compile
    write_dummy_file(Data, Size);

    // Test magic_compile
    magic_compile(magic_cookie, "./dummy_file");

    // Test magic_setflags
    magic_setflags(magic_cookie, param);

    // Clean up
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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
