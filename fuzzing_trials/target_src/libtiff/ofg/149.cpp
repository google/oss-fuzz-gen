#include <tiffio.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h> // Include for close and unlink

extern "C" {

static tmsize_t dummyReadWriteProc(thandle_t, void*, tmsize_t) {
    return 0;
}

static toff_t dummySeekProc(thandle_t, toff_t, int) {
    return 0;
}

static int dummyCloseProc(thandle_t) {
    return 0;
}

static toff_t dummySizeProc(thandle_t) {
    return 0;
}

static int dummyMapFileProc(thandle_t, void**, toff_t*) {
    return 0;
}

static void dummyUnmapFileProc(thandle_t, void*, toff_t) {
}

int LLVMFuzzerTestOneInput_149(const uint8_t *data, size_t size) {
    // Create a temporary file to store the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
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

    // Define dummy I/O procedures
    thandle_t handle = (thandle_t)(intptr_t)fd; // Cast to intptr_t first to avoid warning

    // Call TIFFClientOpenExt with dummy parameters
    TIFF *tiff = TIFFClientOpenExt(
        tmpl, "r", handle,
        dummyReadWriteProc, dummyReadWriteProc,
        dummySeekProc, dummyCloseProc,
        dummySizeProc, dummyMapFileProc,
        dummyUnmapFileProc, nullptr
    );

    // Clean up
    if (tiff) {
        TIFFClose(tiff);
    }
    unlink(tmpl);

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

    LLVMFuzzerTestOneInput_149(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
