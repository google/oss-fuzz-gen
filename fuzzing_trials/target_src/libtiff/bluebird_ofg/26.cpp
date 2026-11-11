#include <sys/stat.h>
#include <string.h>
#include "cstdint"
#include "cstdlib"
#include "cstring"
#include <cstdio>

extern "C" {
    #include "tiffio.h"
}

// Define a structure to hold the data and its size
struct MemoryStream {
    const uint8_t* data;
    size_t size;
    size_t position;
};

// Define the custom I/O functions
static tmsize_t readProc(thandle_t fd, void* buf, tmsize_t size) {
    MemoryStream* stream = (MemoryStream*)fd;
    if (stream->position + size > stream->size) {
        size = stream->size - stream->position;
    }
    memcpy(buf, stream->data + stream->position, size);
    stream->position += size;
    return size;
}

static tmsize_t writeProc(thandle_t, void*, tmsize_t) {
    return 0;
}

static toff_t seekProc(thandle_t fd, toff_t off, int whence) {
    MemoryStream* stream = (MemoryStream*)fd;
    toff_t new_position;
    switch (whence) {
        case SEEK_SET:
            new_position = off;
            break;
        case SEEK_CUR:
            new_position = stream->position + off;
            break;
        case SEEK_END:
            new_position = stream->size + off;
            break;
        default:
            return (toff_t)-1;
    }
    if (new_position < 0 || new_position > stream->size) {
        return (toff_t)-1;
    }
    stream->position = new_position;
    return stream->position;
}

static int closeProc(thandle_t) {
    return 0;
}

static toff_t sizeProc(thandle_t fd) {
    MemoryStream* stream = (MemoryStream*)fd;
    return (toff_t)stream->size;
}

extern "C" int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0;
    }

    // Initialize the memory stream
    MemoryStream stream = {data, size, 0};

    // Use TIFFClientOpen to open a TIFF from memory
    TIFF* tiff = TIFFClientOpen("mem", "r", (thandle_t)&stream, readProc, writeProc, seekProc, closeProc, sizeProc, nullptr, nullptr);
    if (tiff == nullptr) {
        return 0;
    }

    // Attempt to read the directory
    if (TIFFReadDirectory(tiff)) {
        // Process the TIFF data if a directory is successfully read
    }

    TIFFClose(tiff);
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

    LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
