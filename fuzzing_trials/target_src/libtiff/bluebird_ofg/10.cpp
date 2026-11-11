#include <sys/stat.h>
#include <string.h>
#include "tiffio.h"
#include "cstdint"
#include <cstdio>
#include "cstring"

extern "C" {
    // Dummy implementations of the required function pointers
    tsize_t dummyReadWriteProc(thandle_t, tdata_t, tsize_t) {
        return 0;
    }

    toff_t dummySeekProc_10(thandle_t, toff_t, int) {
        return 0;
    }

    int dummyCloseProc_10(thandle_t) {
        return 0;
    }

    toff_t dummySizeProc_10(thandle_t) {
        return 0;
    }

    int dummyMapFileProc(thandle_t, tdata_t*, toff_t*) {
        return 0;
    }

    void dummyUnmapFileProc(thandle_t, tdata_t, toff_t) {
    }

    int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
        if (size < 2) {
            return 0; // Ensure there is enough data for filenames
        }

        // Create null-terminated strings for filenames
        char filename1[256];
        char filename2[256];
        snprintf(filename1, sizeof(filename1), "%.*s", (int)(size / 2), data);
        snprintf(filename2, sizeof(filename2), "%.*s", (int)(size / 2), data + size / 2);

        // Call the function-under-test
        TIFF *tiff = TIFFClientOpen(
            filename1,
            filename2,
            0, // thandle_t handle
            dummyReadWriteProc,
            dummyReadWriteProc,
            dummySeekProc_10,
            dummyCloseProc_10,
            dummySizeProc_10,
            dummyMapFileProc,
            dummyUnmapFileProc
        );

        if (tiff) {
            TIFFClose(tiff);
        }

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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
