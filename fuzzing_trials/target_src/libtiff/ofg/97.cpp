#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h> // Include for the close function

extern "C" {
    #include <tiffio.h> // Wrap TIFF includes with extern "C"
}

extern "C" int LLVMFuzzerTestOneInput_97(const uint8_t *data, size_t size) {
    if (size < sizeof(uint32_t) + sizeof(tmsize_t)) {
        return 0; // Not enough data to extract required parameters
    }

    // Create a temporary file to store the input data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // Failed to create a temporary file
    }

    // Write the input data to the temporary file
    FILE *file = fdopen(fd, "wb");
    if (!file) {
        close(fd);
        return 0;
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the temporary file as a TIFF image
    TIFF *tiff = TIFFOpen(tmpl, "r");
    if (!tiff) {
        remove(tmpl);
        return 0; // Failed to open the file as a TIFF image
    }

    // Extract parameters for TIFFReadRawStrip
    uint32_t strip = *reinterpret_cast<const uint32_t *>(data);
    tmsize_t buffer_size = *reinterpret_cast<const tmsize_t *>(data + sizeof(uint32_t));

    // Ensure buffer_size is not negative and is reasonable
    if (buffer_size <= 0 || buffer_size > static_cast<tmsize_t>(size)) {
        buffer_size = static_cast<tmsize_t>(size);
    }

    // Allocate a buffer for reading
    void *buffer = malloc(buffer_size);
    if (!buffer) {
        TIFFClose(tiff);
        remove(tmpl);
        return 0; // Failed to allocate buffer
    }

    // Call the function-under-test
    TIFFReadRawStrip(tiff, strip, buffer, buffer_size);

    // Clean up
    free(buffer);
    TIFFClose(tiff);
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

    LLVMFuzzerTestOneInput_97(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
