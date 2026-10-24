// This fuzz driver is generated for library libsndfile, aiming to fuzz the following functions:
// sf_error_number at sndfile.c:541:1 in sndfile.h
// sf_get_string at sndfile.c:1619:1 in sndfile.h
// sf_strerror at sndfile.c:563:1 in sndfile.h
// sf_command at sndfile.c:995:1 in sndfile.h
// sf_error_str at sndfile.c:630:1 in sndfile.h
// sf_perror at sndfile.c:609:1 in sndfile.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <sndfile.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

static void fuzz_sf_error_number(int errnum) {
    const char *result = sf_error_number(errnum);
    (void)result; // Suppress unused variable warning
}

static void fuzz_sf_get_string(SNDFILE *sndfile, int str_type) {
    const char *result = sf_get_string(sndfile, str_type);
    (void)result; // Suppress unused variable warning
}

static void fuzz_sf_strerror(SNDFILE *sndfile) {
    const char *result = sf_strerror(sndfile);
    (void)result; // Suppress unused variable warning
}

static void fuzz_sf_command(SNDFILE *sndfile, int command, void *data, int datasize) {
    int result = sf_command(sndfile, command, data, datasize);
    (void)result; // Suppress unused variable warning
}

static void fuzz_sf_error_str(SNDFILE *sndfile, char *str, size_t len) {
    int result = sf_error_str(sndfile, str, len);
    (void)result; // Suppress unused variable warning
}

static void fuzz_sf_perror(SNDFILE *sndfile) {
    int result = sf_perror(sndfile);
    (void)result; // Suppress unused variable warning
}

extern "C" int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    int errnum = *(int *)Data;
    fuzz_sf_error_number(errnum);

    if (Size < 2 * sizeof(int)) return 0;

    int str_type = *(int *)(Data + sizeof(int));
    fuzz_sf_get_string(nullptr, str_type);

    fuzz_sf_strerror(nullptr);

    if (Size < 3 * sizeof(int)) return 0;

    int command = *(int *)(Data + 2 * sizeof(int));
    char dummy_data[256];
    fuzz_sf_command(nullptr, command, dummy_data, sizeof(dummy_data));

    char error_str[256];
    fuzz_sf_error_str(nullptr, error_str, sizeof(error_str));

    fuzz_sf_perror(nullptr);

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

        LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    