extern "C" {
#include <tiffio.h>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>  // Include unistd.h for the 'close' function

// Dummy implementations for the required function pointers
tsize_t dummyReadWriteProc(thandle_t, tdata_t, tsize_t) {
    return 0;
}

toff_t dummySeekProc(thandle_t, toff_t, int) {
    return 0;
}

int dummyCloseProc(thandle_t) {
    return 0;
}

toff_t dummySizeProc(thandle_t) {
    return 0;
}

int dummyMapFileProc(thandle_t, tdata_t*, toff_t*) {
    return 0;
}

void dummyUnmapFileProc(thandle_t, tdata_t, toff_t) {
}

}

extern "C" int LLVMFuzzerTestOneInput_143(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Create a temporary file to simulate a TIFF file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    FILE *file = fdopen(fd, "wb");
    if (!file) {
        close(fd);
        return 0;
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the TIFF using the TIFFClientOpen function
    TIFF *tiff = TIFFClientOpen(
        tmpl, "r", nullptr,
        dummyReadWriteProc, dummyReadWriteProc,
        dummySeekProc, dummyCloseProc,
        dummySizeProc, dummyMapFileProc,
        dummyUnmapFileProc
    );

    // Clean up
    if (tiff) {
        TIFFClose(tiff);
    }
    remove(tmpl);

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

    LLVMFuzzerTestOneInput_143(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
