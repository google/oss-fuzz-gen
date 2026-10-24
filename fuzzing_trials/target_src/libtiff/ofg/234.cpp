#include <tiffio.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

extern "C" int LLVMFuzzerTestOneInput_234(const uint8_t *data, size_t size) {
    // Create a temporary file to write the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return 0;
    }

    // Rewind the file descriptor to the beginning
    lseek(fd, 0, SEEK_SET);

    // Open the TIFF file using the temporary filename
    TIFF *tiff = TIFFFdOpen(fd, tmpl, "r");
    if (tiff == nullptr) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Initialize parameters for the function-under-test
    uint32_t strile = 0; // Example value, can be varied for more thorough testing
    int error = 0;

    // Call the function-under-test
    uint64_t offset = TIFFGetStrileOffsetWithErr(tiff, strile, &error);

    // Cleanup
    TIFFClose(tiff);
    close(fd);
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

    LLVMFuzzerTestOneInput_234(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
