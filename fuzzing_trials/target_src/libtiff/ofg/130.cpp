#include <tiffio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <cstring>  // Include this header for memcpy

extern "C" {

// Define a custom error handler function
void customErrorHandler_130(const char* module, const char* fmt, va_list ap) {
    // Custom error handling logic can be implemented here
    // For this fuzzing purpose, we'll just ignore the errors
}

int LLVMFuzzerTestOneInput_130(const uint8_t *data, size_t size) {
    // Ensure that the data size is non-zero to avoid unnecessary calls
    if (size == 0) {
        return 0;
    }

    // Set the custom error handler
    TIFFErrorHandler previousHandler = TIFFSetErrorHandler(customErrorHandler_130);

    // Create a memory buffer to hold the input data
    TIFF* tiff = TIFFClientOpen("memory", "r", (thandle_t)data,
                                [](thandle_t fd, tdata_t buf, tsize_t read_size) -> tsize_t {
                                    memcpy(buf, (void*)fd, read_size);
                                    return read_size;
                                },
                                [](thandle_t fd, tdata_t buf, tsize_t write_size) -> tsize_t {
                                    return 0;
                                },
                                [](thandle_t fd, toff_t off, int whence) -> toff_t {
                                    if (whence == SEEK_SET) {
                                        return (toff_t)off;
                                    } else if (whence == SEEK_CUR) {
                                        return (toff_t)off;
                                    } else if (whence == SEEK_END) {
                                        return (toff_t)off;
                                    }
                                    return 0;
                                },
                                [](thandle_t fd) -> int {
                                    return 0;
                                },
                                [](thandle_t fd) -> toff_t {
                                    return 0;
                                },
                                [](thandle_t fd, void** pbase, toff_t* psize) -> int {
                                    return 0;
                                },
                                [](thandle_t fd, void* base, toff_t size) -> void {
                                    // Unmap logic can be added here if needed
                                }
                                );

    if (tiff) {
        // Read the directory to test some basic functionality
        TIFFReadDirectory(tiff);
        TIFFClose(tiff);
    }

    // Optionally, you can restore the previous error handler if needed
    TIFFSetErrorHandler(previousHandler);

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

    LLVMFuzzerTestOneInput_130(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
