#include <cstdint>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <tiffio.h>

extern "C" {
    TIFFCloseProc TIFFGetCloseProc(TIFF *);
}

extern "C" int LLVMFuzzerTestOneInput_115(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Create a temporary file to write the data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the data to the file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Close the file descriptor
    close(fd);

    // Open the TIFF file
    TIFF *tiff = TIFFOpen(tmpl, "r");
    if (tiff == nullptr) {
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    TIFFCloseProc closeProc = TIFFGetCloseProc(tiff);

    // Use the closeProc if necessary (here we just demonstrate retrieval)
    if (closeProc != nullptr) {
        // Typically, you would use the closeProc here, but for fuzzing, we're just testing retrieval
    }

    // Close the TIFF file
    TIFFClose(tiff);

    // Remove the temporary file
    unlink(tmpl);

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

    LLVMFuzzerTestOneInput_115(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
