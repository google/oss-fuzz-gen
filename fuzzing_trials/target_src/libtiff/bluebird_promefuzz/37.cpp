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
#include "tiffio.h"
#include <unistd.h>
#include <fcntl.h>

extern "C" int LLVMFuzzerTestOneInput_37(const uint8_t *Data, size_t Size) {
    // Write the input data to a dummy file
    const char *filename = "./dummy_file";
    int fd = open(filename, O_RDWR | O_CREAT, 0666);
    if (fd < 0) {
        return 0;
    }
    if (write(fd, Data, Size) != static_cast<ssize_t>(Size)) {
        close(fd);
        return 0;
    }
    lseek(fd, 0, SEEK_SET);

    // Allocate TIFFOpenOptions
    TIFFOpenOptions *opts = TIFFOpenOptionsAlloc();
    if (!opts) {
        close(fd);
        return 0;
    }

    // Set options
    TIFFOpenOptionsSetWarnAboutUnknownTags(opts, 1);
    TIFFOpenOptionsSetMaxSingleMemAlloc(opts, 1024 * 1024); // Example: 1MB

    // Fuzz TIFFFdOpenExt
    TIFF *tif_fd = TIFFFdOpenExt(fd, filename, "r", opts);
    if (tif_fd) {
        TIFFClose(tif_fd);
    }

    // Fuzz TIFFOpenExt
    TIFF *tif_file = TIFFOpenExt(filename, "r", opts);
    if (tif_file) {
        TIFFClose(tif_file);
    }

    // Cleanup
    TIFFOpenOptionsFree(opts);
    close(fd);
    unlink(filename);

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

    LLVMFuzzerTestOneInput_37(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
