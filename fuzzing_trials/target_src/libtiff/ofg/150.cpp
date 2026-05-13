#include <tiffio.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h> // Needed for close()

extern "C" {

static tmsize_t readProc(thandle_t, void*, tmsize_t) {
    return 0; // Dummy implementation
}

static tmsize_t writeProc(thandle_t, void*, tmsize_t) {
    return 0; // Dummy implementation
}

static toff_t seekProc(thandle_t, toff_t, int) {
    return 0; // Dummy implementation
}

static int closeProc(thandle_t) {
    return 0; // Dummy implementation
}

static toff_t sizeProc(thandle_t) {
    return 0; // Dummy implementation
}

static int mapProc(thandle_t, void**, toff_t*) {
    return 0; // Dummy implementation
}

static void unmapProc(thandle_t, void*, toff_t) {
    // Dummy implementation
}

int LLVMFuzzerTestOneInput_150(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    // Create a temporary filename for testing
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    FILE* file = fdopen(fd, "wb");
    if (!file) {
        close(fd);
        return 0;
    }

    // Write the fuzz data to the file
    fwrite(data, 1, size, file);
    fclose(file);

    TIFFOpenOptions *options = TIFFOpenOptionsAlloc();
    if (!options) {
        remove(tmpl);
        return 0;
    }

    TIFF *tiff = TIFFClientOpenExt(
        tmpl, "r", (thandle_t)(intptr_t)fd, readProc, writeProc, seekProc, closeProc, sizeProc, mapProc, unmapProc, options
    );

    if (tiff) {
        TIFFClose(tiff);
    }

    TIFFOpenOptionsFree(options);
    remove(tmpl);
    close(fd); // Ensure the file descriptor is closed
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

    LLVMFuzzerTestOneInput_150(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
