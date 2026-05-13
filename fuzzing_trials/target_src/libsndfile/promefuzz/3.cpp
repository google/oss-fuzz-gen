// This fuzz driver is generated for library libsndfile, aiming to fuzz the following functions:
// sf_error_number at sndfile.c:541:1 in sndfile.h
// sf_open at sndfile.c:348:1 in sndfile.h
// sf_get_string at sndfile.c:1619:1 in sndfile.h
// sf_strerror at sndfile.c:563:1 in sndfile.h
// sf_command at sndfile.c:995:1 in sndfile.h
// sf_error_str at sndfile.c:630:1 in sndfile.h
// sf_perror at sndfile.c:609:1 in sndfile.h
// sf_close at sndfile.c:517:1 in sndfile.h
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
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0;
    }

    int errnum = *(reinterpret_cast<const int*>(Data));
    const char* error_number_str = sf_error_number(errnum);
    if (error_number_str) {
        printf("sf_error_number(%d): %s\n", errnum, error_number_str);
    }

    // Prepare a dummy SNDFILE object and a dummy file
    FILE *dummy_file = fopen("./dummy_file", "wb+");
    if (!dummy_file) {
        return 0;
    }

    SF_INFO sfinfo;
    memset(&sfinfo, 0, sizeof(sfinfo));
    SNDFILE *sndfile = sf_open("./dummy_file", SFM_RDWR, &sfinfo);

    if (sndfile) {
        int str_type = *(reinterpret_cast<const int*>(Data + sizeof(int)));
        const char* get_string = sf_get_string(sndfile, str_type);
        if (get_string) {
            printf("sf_get_string: %s\n", get_string);
        }

        const char* strerror_str = sf_strerror(sndfile);
        if (strerror_str) {
            printf("sf_strerror: %s\n", strerror_str);
        }

        int command = *(reinterpret_cast<const int*>(Data + 2 * sizeof(int)));
        char command_data[256];
        int command_result = sf_command(sndfile, command, command_data, sizeof(command_data));
        printf("sf_command result: %d\n", command_result);

        char error_str[256];
        int error_str_result = sf_error_str(sndfile, error_str, sizeof(error_str));
        printf("sf_error_str result: %d, message: %s\n", error_str_result, error_str);

        int perror_result = sf_perror(sndfile);
        printf("sf_perror result: %d\n", perror_result);

        sf_close(sndfile);
    }

    fclose(dummy_file);
    remove("./dummy_file");

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

        LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    