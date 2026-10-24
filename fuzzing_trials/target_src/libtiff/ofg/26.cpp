#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>  // Include this header for the 'close' function

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0; // Not enough data to proceed
    }

    // Create a temporary file to write the TIFF data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // Failed to create a temporary file
    }

    // Write the input data to the temporary file
    FILE *file = fdopen(fd, "wb");
    if (file == NULL) {
        close(fd);
        return 0;
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the TIFF file
    TIFF *tiff = TIFFOpen(tmpl, "r");
    if (tiff == NULL) {
        remove(tmpl);
        return 0; // Failed to open the TIFF file
    }

    // Prepare a tag to query
    uint32_t tag = *(uint32_t *)data;

    // Prepare a buffer for the field value
    void *value = malloc(1024); // Allocate a buffer of 1024 bytes

    // Call the function-under-test
    TIFFGetField(tiff, tag, value);

    // Clean up
    free(value);
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

    LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
