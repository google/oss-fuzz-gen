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
#include <cstdlib>
#include <cstring>
#include <cstdio>

extern "C" int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare a dummy file for SNDFILE operations
    const char *dummyFileName = "./dummy_file";
    FILE *dummyFile = fopen(dummyFileName, "wb");
    if (!dummyFile) return 0;

    fwrite(Data, 1, Size, dummyFile);
    fclose(dummyFile);

    // Open the dummy file with libsndfile
    SF_INFO sfinfo;
    SNDFILE *sndfile = sf_open(dummyFileName, SFM_READ, &sfinfo);

    // 1. Test sf_error_number
    int errnum = Data[0];
    const char *errorDesc = sf_error_number(errnum);
    (void)errorDesc; // Suppress unused variable warning

    // 2. Test sf_strerror
    const char *strError = sf_strerror(sndfile);
    (void)strError; // Suppress unused variable warning

    // 3. Test sf_error
    int errorCode = sf_error(sndfile);
    (void)errorCode; // Suppress unused variable warning

    // 4. Test sf_error_str
    char errorStr[256];
    int errorStrResult = sf_error_str(sndfile, errorStr, sizeof(errorStr));
    (void)errorStrResult; // Suppress unused variable warning

    // 5. Test sf_current_byterate
    int byteRate = sf_current_byterate(sndfile);
    (void)byteRate; // Suppress unused variable warning

    // 6. Test sf_perror
    int perrorResult = sf_perror(sndfile);
    (void)perrorResult; // Suppress unused variable warning

    // Cleanup
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

    LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
