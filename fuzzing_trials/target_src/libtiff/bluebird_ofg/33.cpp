#include <sys/stat.h>
#include <string.h>
#include "tiffio.h"
#include <cstddef>
#include "cstdint"
#include <cstdio>
#include "cstdlib"
#include <unistd.h>  // Include for close()

extern "C" {

tsize_t dummyReadProc(thandle_t, tdata_t, tsize_t);
tsize_t dummyWriteProc(thandle_t, tdata_t, tsize_t);
toff_t dummySeekProc_33(thandle_t, toff_t, int);
int dummyCloseProc_33(thandle_t);
toff_t dummySizeProc_33(thandle_t);
int dummyMapProc(thandle_t, tdata_t*, toff_t*);
void dummyUnmapProc(thandle_t, tdata_t, toff_t);

tsize_t dummyReadProc(thandle_t, tdata_t, tsize_t) {
    return 0;
}

tsize_t dummyWriteProc(thandle_t, tdata_t, tsize_t) {
    return 0;
}

toff_t dummySeekProc_33(thandle_t, toff_t, int) {
    return 0;
}

int dummyCloseProc_33(thandle_t) {
    return 0;
}

toff_t dummySizeProc_33(thandle_t) {
    return 0;
}

int dummyMapProc(thandle_t, tdata_t*, toff_t*) {
    return 0;
}

void dummyUnmapProc(thandle_t, tdata_t, toff_t) {
}

int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    char filename[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(filename);
    if (fd == -1) {
        return 0;
    }

    FILE *file = fdopen(fd, "wb");
    if (!file) {
        close(fd);
        return 0;
    }

    fwrite(data, 1, size, file);
    fclose(file);

    TIFFOpenOptions *options = TIFFOpenOptionsAlloc();
    TIFF *tiff = TIFFClientOpenExt(
        filename, 
        "r", 
        (thandle_t)nullptr, 
        dummyReadProc, 
        dummyWriteProc, 
        dummySeekProc_33, 
        dummyCloseProc_33, 
        dummySizeProc_33, 
        dummyMapProc, 
        dummyUnmapProc, 
        options
    );

    if (tiff) {
        TIFFClose(tiff);
    }

    TIFFOpenOptionsFree(options);
    remove(filename);

    return 0;
}

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

    LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
