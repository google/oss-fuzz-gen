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
#include <iostream>
#include <fstream>

static void writeDummyFile(const uint8_t *Data, size_t Size) {
    std::ofstream outfile("./dummy_file", std::ios::binary);
    outfile.write(reinterpret_cast<const char*>(Data), Size);
    outfile.close();
}

extern "C" int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    // Step 1: Write the input data to a dummy file
    writeDummyFile(Data, Size);

    // Step 2: Open the file using libsndfile
    SF_INFO sfinfo;
    memset(&sfinfo, 0, sizeof(sfinfo));
    SNDFILE *sndfile = sf_open("./dummy_file", SFM_READ, &sfinfo);
    if (!sndfile) return 0;

    // Step 3: Prepare buffers for reading
    int intBuffer[1024];
    double doubleBuffer[1024];
    short shortBuffer[1024];
    char rawBuffer[1024];

    // Step 4: Fuzz sf_read_int
    sf_read_int(sndfile, intBuffer, sizeof(intBuffer) / sizeof(int));

    // Step 5: Fuzz sf_format_check
    sf_format_check(&sfinfo);

    // Step 6: Fuzz sf_read_double
    sf_read_double(sndfile, doubleBuffer, sizeof(doubleBuffer) / sizeof(double));

    // Step 7: Fuzz sf_write_raw (requires a writable file)
    SNDFILE *writeFile = sf_open("./dummy_file", SFM_WRITE, &sfinfo);
    if (writeFile) {
        sf_write_raw(writeFile, Data, Size);
        sf_close(writeFile);
    }

    // Step 8: Fuzz sf_read_short
    sf_read_short(sndfile, shortBuffer, sizeof(shortBuffer) / sizeof(short));

    // Step 9: Fuzz sf_read_raw
    sf_read_raw(sndfile, rawBuffer, sizeof(rawBuffer));

    // Step 10: Clean up
    sf_close(sndfile);

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

    LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
