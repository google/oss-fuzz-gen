#include <sys/stat.h>
#include <string.h>
#include "cstdint"
#include <cstdio>
#include <cstdarg>
#include "cstring"  // Include for memcpy
#include "tiffio.h"

extern "C" {

// A custom warning handler to be used with TIFFSetWarningHandlerExt
void customWarningHandler_54(void* user_data, const char* module, const char* fmt, va_list ap) {
    fprintf(stderr, "Custom Warning: ");
    if (module != nullptr) {
        fprintf(stderr, "%s: ", module);
    }
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}

// Custom read function for TIFFClientOpen
tsize_t readProc(thandle_t fd, tdata_t buf, tsize_t size) {
    auto* data = reinterpret_cast<const uint8_t*>(fd);
    // Ensure we don't read beyond the provided buffer
    size_t remaining = *reinterpret_cast<const size_t*>(data + sizeof(uint8_t*));
    if (size > remaining) {
        size = remaining;
    }
    memcpy(buf, data, size);
    // Update the remaining size
    *const_cast<size_t*>(reinterpret_cast<const size_t*>(data + sizeof(uint8_t*))) -= size;
    return size;
}

// Custom write function for TIFFClientOpen
tsize_t writeProc(thandle_t fd, tdata_t buf, tsize_t size) {
    return 0;
}

// Custom seek function for TIFFClientOpen
toff_t seekProc(thandle_t fd, toff_t off, int whence) {
    const uint8_t* base = reinterpret_cast<const uint8_t*>(fd);
    uint8_t* data = const_cast<uint8_t*>(base);
    switch (whence) {
        case SEEK_SET:
            data = const_cast<uint8_t*>(base) + off;
            break;
        case SEEK_CUR:
            data += off;
            break;
        case SEEK_END:
            // Assuming fd points to the end of the buffer
            data = const_cast<uint8_t*>(base) + off; 
            break;
        default:
            return -1;
    }
    return data - base;
}

// Custom close function for TIFFClientOpen
int closeProc(thandle_t fd) {
    return 0;
}

// Custom size function for TIFFClientOpen
toff_t sizeProc(thandle_t fd) {
    const uint8_t* data = reinterpret_cast<const uint8_t*>(fd);
    return *reinterpret_cast<const size_t*>(data + sizeof(uint8_t*));
}

// Custom map function for TIFFClientOpen
int mapProc(thandle_t fd, tdata_t* pbase, toff_t* psize) {
    return 0;
}

// Custom unmap function for TIFFClientOpen
void unmapProc(thandle_t fd, tdata_t base, toff_t size) {
}

int LLVMFuzzerTestOneInput_54(const uint8_t *data, size_t size) {
    // Ensure that the data size is sufficient to be used meaningfully
    if (size < sizeof(size_t)) {
        return 0;
    }

    // Allocate a buffer to hold the data and size
    uint8_t* buffer = new uint8_t[size + sizeof(size_t)];
    memcpy(buffer, data, size);
    *reinterpret_cast<size_t*>(buffer + size) = size;

    // Set a custom warning handler using TIFFSetWarningHandlerExt
    TIFFErrorHandlerExt prevHandler = TIFFSetWarningHandlerExt(customWarningHandler_54);

    // Use TIFFClientOpen to open the data as a TIFF image
    TIFF* tif = TIFFClientOpen("memory", "r", (thandle_t)buffer, readProc, writeProc, seekProc, closeProc, sizeProc, mapProc, unmapProc);
    if (tif) {
        // Perform operations on the TIFF file, if needed
        TIFFClose(tif);
    }

    // Optionally, you can restore the previous handler if needed
    // TIFFSetWarningHandlerExt(prevHandler);

    // Clean up the allocated buffer
    delete[] buffer;

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

    LLVMFuzzerTestOneInput_54(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
