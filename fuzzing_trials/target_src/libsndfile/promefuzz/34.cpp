// This fuzz driver is generated for library libsndfile, aiming to fuzz the following functions:
// sf_error_number at sndfile.c:541:1 in sndfile.h
// sf_open at sndfile.c:348:1 in sndfile.h
// sf_strerror at sndfile.c:563:1 in sndfile.h
// sf_error at sndfile.c:591:1 in sndfile.h
// sf_error_str at sndfile.c:630:1 in sndfile.h
// sf_error_str at sndfile.c:630:1 in sndfile.h
// sf_current_byterate at sndfile.c:1643:1 in sndfile.h
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
extern "C" {
#include <sndfile.h>
}

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = std::fopen("./dummy_file", "wb");
    if (file) {
        std::fwrite(Data, 1, Size, file);
        std::fclose(file);
    }
}

extern "C" int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0;
    }

    write_dummy_file(Data, Size);

    // Error number from input data
    int errnum = *reinterpret_cast<const int*>(Data);

    // Test sf_error_number
    const char* error_str = sf_error_number(errnum);
    if (error_str) {
        std::puts(error_str);
    }

    // Open a dummy sound file
    SF_INFO sfinfo;
    std::memset(&sfinfo, 0, sizeof(SF_INFO));
    SNDFILE *sndfile = sf_open("./dummy_file", SFM_READ, &sfinfo);

    // Test sf_strerror
    const char* strerror_msg = sf_strerror(sndfile);
    if (strerror_msg) {
        std::puts(strerror_msg);
    }

    // Test sf_error
    int error_code = sf_error(sndfile);
    (void)error_code; // To avoid unused variable warning

    // Test sf_error_str
    char error_buffer[256];
    if (sndfile) {
        sf_error_str(sndfile, error_buffer, sizeof(error_buffer));
    } else {
        sf_error_str(NULL, error_buffer, sizeof(error_buffer));
    }
    std::puts(error_buffer);

    // Test sf_current_byterate
    int byterate = sf_current_byterate(sndfile);
    (void)byterate; // To avoid unused variable warning

    // Test sf_perror
    sf_perror(sndfile);

    // Clean up
    if (sndfile) {
        sf_close(sndfile);
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

        LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    