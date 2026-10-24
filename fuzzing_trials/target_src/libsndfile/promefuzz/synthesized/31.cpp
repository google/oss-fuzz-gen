// This fuzz driver is generated for library libsndfile, aiming to fuzz the following functions:
// sf_error_number at sndfile.c:541:1 in sndfile.h
// sf_strerror at sndfile.c:563:1 in sndfile.h
// sf_error at sndfile.c:591:1 in sndfile.h
// sf_error_str at sndfile.c:630:1 in sndfile.h
// sf_current_byterate at sndfile.c:1643:1 in sndfile.h
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

extern "C" int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    // Extract an integer for sf_error_number
    int errnum = *reinterpret_cast<const int*>(Data);
    
    // Test sf_error_number
    const char* errorNumberStr = sf_error_number(errnum);
    if (errorNumberStr) {
        printf("sf_error_number: %s\n", errorNumberStr);
    }

    // Prepare a dummy SNDFILE pointer for other tests
    SNDFILE* sndfile = nullptr;

    // Test sf_strerror
    const char* strerrorStr = sf_strerror(sndfile);
    if (strerrorStr) {
        printf("sf_strerror: %s\n", strerrorStr);
    }

    // Test sf_error
    int error = sf_error(sndfile);
    printf("sf_error: %d\n", error);

    // Test sf_error_str
    char errorStr[256];
    int errorStrResult = sf_error_str(sndfile, errorStr, sizeof(errorStr));
    if (errorStrResult == 0) {
        printf("sf_error_str: %s\n", errorStr);
    } else {
        printf("sf_error_str failed\n");
    }

    // Test sf_current_byterate
    int byterate = sf_current_byterate(sndfile);
    printf("sf_current_byterate: %d\n", byterate);

    // Test sf_perror
    int perrorResult = sf_perror(sndfile);
    printf("sf_perror: %d\n", perrorResult);

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

        LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    