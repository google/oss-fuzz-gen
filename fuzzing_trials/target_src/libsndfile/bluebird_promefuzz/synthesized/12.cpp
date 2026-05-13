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
#include "sndfile.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_12(const uint8_t *Data, size_t Size) {
    // Prepare a dummy file for testing SNDFILE-related functions
    const char *dummyFileName = "./dummy_file";
    FILE *dummyFile = fopen(dummyFileName, "wb");
    if (!dummyFile) {
        return 0;
    }
    fwrite(Data, 1, Size, dummyFile);
    fclose(dummyFile);

    // Open the dummy file with libsndfile
    SF_INFO sfinfo;
    memset(&sfinfo, 0, sizeof(sfinfo));
    SNDFILE *sndfile = sf_open(dummyFileName, SFM_READ, &sfinfo);

    // Test sf_error_number with random data
    if (Size >= sizeof(int)) {
        int errnum;
        memcpy(&errnum, Data, sizeof(int));
        const char *errorStr = sf_error_number(errnum);
        if (errorStr) {
            // Do something with the errorStr, like logging
        }
    }

    // Test sf_strerror
    const char *strError = sf_strerror(sndfile);
    if (strError) {
        // Do something with strError, like logging
    }

    // Test sf_error
    int lastError = sf_error(sndfile);
    // Do something with lastError, like logging

    // Test sf_error_str
    char errorBuffer[256];
    sf_error_str(sndfile, errorBuffer, sizeof(errorBuffer));
    // Do something with errorBuffer, like logging

    // Test sf_current_byterate
    int byteRate = sf_current_byterate(sndfile);
    // Do something with byteRate, like logging

    // Test sf_perror
    sf_perror(sndfile);

    // Clean up
    if (sndfile) {
        sf_close(sndfile);
    }
    remove(dummyFileName);

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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
