#include <tiffio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>  // Include for unlink, close, and write
#include <fcntl.h>   // Include for mkstemp

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    // Create a temporary file to write the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }
    close(fd);

    // Open the temporary file as a TIFF image
    TIFF *tiff = TIFFOpen(tmpl, "r");
    if (tiff == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Prepare parameters for TIFFReadEncodedStrip
    uint32_t strip = 0; // Starting with the first strip
    tmsize_t buf_size = TIFFStripSize(tiff);
    void *buf = malloc(buf_size);
    if (buf == NULL) {
        TIFFClose(tiff);
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    TIFFReadEncodedStrip(tiff, strip, buf, buf_size);

    // Clean up
    free(buf);
    TIFFClose(tiff);
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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
