#include <tiffio.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>  // Include for the 'close' function

extern "C" {
    // Include necessary C headers, source files, functions, and code here.
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_177(const uint8_t *data, size_t size) {
    // Create a temporary file to store the input data
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

    // Open the temporary file with TIFFOpen
    TIFF *tiff = TIFFOpen(tmpl, "r");
    if (tiff) {
        // Call the function-under-test
        TIFFMapFileProc mapFileProc = TIFFGetMapFileProc(tiff);

        // Use the function pointer returned by TIFFGetMapFileProc
        if (mapFileProc) {
            // Dummy variables for demonstration, as we don't have actual file mapping
            void *base = nullptr;
            toff_t size = 0;
            mapFileProc(tiff, &base, &size);
        }

        // Close the TIFF file
        TIFFClose(tiff);
    }

    // Remove the temporary file
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

    LLVMFuzzerTestOneInput_177(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
