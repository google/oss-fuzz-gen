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

extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0;
    }

    int errnum;
    memcpy(&errnum, Data, sizeof(int));
    const char *error_num_str = sf_error_number(errnum);

    // Fuzzing sf_get_string
    SNDFILE *sndfile = nullptr;  // A null SNDFILE pointer for testing
    int str_type = errnum;  // Reusing errnum as str_type for simplicity
    const char *get_string_str = sf_get_string(sndfile, str_type);

    // Fuzzing sf_strerror
    const char *strerror_str = sf_strerror(sndfile);

    // Fuzzing sf_command
    int command = errnum;  // Reusing errnum as command
    char command_data[256];  // Dummy data buffer
    int command_result = sf_command(sndfile, command, command_data, sizeof(command_data));

    // Fuzzing sf_error_str
    char error_str[256];
    int error_str_result = sf_error_str(sndfile, error_str, sizeof(error_str));

    // Fuzzing sf_perror
    int perror_result = sf_perror(sndfile);

    // Output to suppress unused variable warnings
    (void)error_num_str;
    (void)get_string_str;
    (void)strerror_str;
    (void)command_result;
    (void)error_str_result;
    (void)perror_result;

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

        LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    