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
#include "cstdint"
#include <cstdio>
#include "cstdlib"
#include "cstring"
#include "tiffio.h"

static TIFF* openDummyTIFFFile(const char* mode) {
    FILE* file = std::fopen("./dummy_file", mode);
    if (!file) {
        return nullptr;
    }
    std::fclose(file);
    return TIFFOpen("./dummy_file", mode);
}

extern "C" int LLVMFuzzerTestOneInput_36(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0;
    }

    // Open a TIFF file for writing
    TIFF* tif = openDummyTIFFFile("w+");
    if (!tif) {
        return 0;
    }

    // 1. Fuzz TIFFDeferStrileArrayWriting
    int deferResult = TIFFDeferStrileArrayWriting(tif);

    // 2. Fuzz TIFFCheckpointDirectory
    int checkpointResult = TIFFCheckpointDirectory(tif);

    // 3. Fuzz TIFFSetMode
    int mode = *reinterpret_cast<const int*>(Data);
    int previousMode = TIFFSetMode(tif, mode);

    // 4. Fuzz TIFFReadBufferSetup
    void* readBuffer = nullptr;
    tmsize_t readBufferSize = static_cast<tmsize_t>(Size);
    int readBufferSetupResult = TIFFReadBufferSetup(tif, readBuffer, readBufferSize);

    // 5. Fuzz TIFFFlush
    int flushResult = TIFFFlush(tif);

    // 6. Fuzz TIFFWriteBufferSetup
    void* writeBuffer = nullptr;
    tmsize_t writeBufferSize = static_cast<tmsize_t>(Size);
    int writeBufferSetupResult = TIFFWriteBufferSetup(tif, writeBuffer, writeBufferSize);

    // Cleanup
    TIFFClose(tif);

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

    LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
