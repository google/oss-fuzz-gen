#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>  // For close()
#include <cstring>   // For memcpy()

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_159(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0; // Ensure there's enough data for a uint32_t
    }

    // Create a temporary file to write the input data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // Failed to create a temp file
    }

    FILE *file = fdopen(fd, "wb");
    if (!file) {
        close(fd);
        return 0;
    }

    // Write the input data to the file
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the TIFF file
    TIFF *tiff = TIFFOpen(tmpl, "r");
    if (!tiff) {
        remove(tmpl);
        return 0; // Failed to open the TIFF file
    }

    // Extract a uint32_t tag from the input data
    uint32_t tag;
    memcpy(&tag, data, sizeof(uint32_t));

    // Prepare a buffer for the value
    char value[256]; // Adjust size as needed

    // Call the function-under-test
    TIFFGetFieldDefaulted(tiff, tag, value);

    // Clean up
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

    LLVMFuzzerTestOneInput_159(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
