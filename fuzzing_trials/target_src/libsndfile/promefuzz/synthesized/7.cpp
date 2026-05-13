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
#include <cstdlib>
#include <cstring>
#include <iostream>

static void fuzz_sf_error_number(int errnum) {
    const char *error_str = sf_error_number(errnum);
    if (error_str) {
        std::cout << "Error Number: " << errnum << " - " << error_str << std::endl;
    }
}

static void fuzz_sf_get_string(SNDFILE *sndfile, int str_type) {
    const char *str = sf_get_string(sndfile, str_type);
    if (str) {
        std::cout << "String Type: " << str_type << " - " << str << std::endl;
    }
}

static void fuzz_sf_strerror(SNDFILE *sndfile) {
    const char *error_str = sf_strerror(sndfile);
    if (error_str) {
        std::cout << "StrError: " << error_str << std::endl;
    }
}

static void fuzz_sf_command(SNDFILE *sndfile, int command, void *data, int datasize) {
    int result = sf_command(sndfile, command, data, datasize);
    std::cout << "Command Result: " << result << std::endl;
}

static void fuzz_sf_error_str(SNDFILE *sndfile, char *str, size_t len) {
    int result = sf_error_str(sndfile, str, len);
    if (result == 0) {
        std::cout << "Error String: " << str << std::endl;
    }
}

static void fuzz_sf_perror(SNDFILE *sndfile) {
    sf_perror(sndfile);
}

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy SNDFILE pointer
    SNDFILE *sndfile = nullptr;

    // Use the first byte to determine the function to fuzz
    int choice = Data[0] % 6;
    int errnum = 0;
    int str_type = 0;
    int command = 0;
    char buffer[256] = {0};

    // Create a dummy file if needed
    FILE *dummy_file = fopen("./dummy_file", "wb+");
    if (dummy_file) {
        fwrite(Data, 1, Size, dummy_file);
        fclose(dummy_file);
    }

    switch (choice) {
        case 0:
            // Fuzz sf_error_number
            if (Size >= 1 + sizeof(int)) {
                memcpy(&errnum, Data + 1, sizeof(int));
                fuzz_sf_error_number(errnum);
            }
            break;
        case 1:
            // Fuzz sf_get_string
            if (Size >= 1 + sizeof(int)) {
                memcpy(&str_type, Data + 1, sizeof(int));
                fuzz_sf_get_string(sndfile, str_type);
            }
            break;
        case 2:
            // Fuzz sf_strerror
            fuzz_sf_strerror(sndfile);
            break;
        case 3:
            // Fuzz sf_command
            if (Size >= 1 + sizeof(int) * 2) {
                memcpy(&command, Data + 1, sizeof(int));
                fuzz_sf_command(sndfile, command, buffer, sizeof(buffer));
            }
            break;
        case 4:
            // Fuzz sf_error_str
            fuzz_sf_error_str(sndfile, buffer, sizeof(buffer));
            break;
        case 5:
            // Fuzz sf_perror
            fuzz_sf_perror(sndfile);
            break;
    }

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

        LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    