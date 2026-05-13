#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include "sstream"
#include <string>
#include <vector>
#include "cstring"
#include "cstdlib"
#include <cstdio>
#include "cstdint"
#include <cstddef>
#include <iostream>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include "tiffio.h"

extern "C" int LLVMFuzzerTestOneInput_70(const uint8_t *Data, size_t Size) {
    // Step 1: Prepare environment
    const char *dummyFileName = "./dummy_file";
    std::ofstream dummyFile(dummyFileName, std::ios::binary);
    if (!dummyFile.is_open()) {
        return 0;
    }
    dummyFile.write(reinterpret_cast<const char *>(Data), Size);
    dummyFile.close();

    // Open the dummy file to get a file descriptor
    int fd = open(dummyFileName, O_RDWR);
    if (fd < 0) {
        return 0;
    }

    // Step 2: Invoke TIFFFdOpen
    TIFF *tiff = TIFFFdOpen(fd, dummyFileName, "r");
    if (!tiff) {
        close(fd);
        return 0;
    }

    // Step 3: Explore program states
    // Check if the TIFF is a BigTIFF
    TIFFIsBigTIFF(tiff);

    // Check if the TIFF is ready for writing
    TIFFWriteCheck(tiff, 1, "test");

    // Set subdirectory
    uint64_t offset = 0;
    if (Size >= sizeof(uint64_t)) {
        offset = *reinterpret_cast<const uint64_t *>(Data);
    }
    TIFFSetSubDirectory(tiff, offset);

    // Write directory
    TIFFWriteDirectory(tiff);

    // Read directory
    TIFFReadDirectory(tiff);

    // Step 4: Cleanup
    TIFFClose(tiff);
    close(fd);

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

    LLVMFuzzerTestOneInput_70(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
