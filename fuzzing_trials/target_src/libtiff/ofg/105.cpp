extern "C" {
    #include <tiffio.h>
    #include <stdint.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h> // Include for close, unlink, and write
}

extern "C" int LLVMFuzzerTestOneInput_105(const uint8_t *data, size_t size) {
    TIFF *tiff;
    uint32_t tileIndex = 0;
    tmsize_t bufferSize = 1024; // Arbitrary buffer size
    void *buffer = malloc(bufferSize);

    // Create a temporary file to store the input data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        free(buffer);
        return 0;
    }
    write(fd, data, size);
    close(fd);

    // Open the TIFF file
    tiff = TIFFOpen(tmpl, "r");
    if (tiff != NULL) {
        // Call the function-under-test
        TIFFReadEncodedTile(tiff, tileIndex, buffer, bufferSize);

        // Close the TIFF file
        TIFFClose(tiff);
    }

    // Clean up
    free(buffer);
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

    LLVMFuzzerTestOneInput_105(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
