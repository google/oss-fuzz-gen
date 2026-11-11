#include <stdint.h>
#include <stdio.h>
#include <unistd.h>  // Include for 'write', 'close', 'mkstemp'
#include <fcntl.h>   // Include for file control options
#include <stdlib.h>  // Include for 'mkstemp' declaration

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_220(const uint8_t *data, size_t size) {
    // Create a temporary file to write the input data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // If file creation fails, return early
    }

    // Write the data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        return 0; // If writing fails, return early
    }

    // Close the file descriptor
    close(fd);

    // Open the TIFF file
    TIFF* tif = TIFFOpen(tmpl, "r");
    if (tif == NULL) {
        remove(tmpl);
        return 0; // If TIFFOpen fails, return early
    }

    // Call the function-under-test
    tmsize_t scanlineSize = TIFFRasterScanlineSize(tif);

    // Optionally print the result for debugging purposes
    printf("Scanline Size: %td\n", scanlineSize);

    // Close the TIFF file
    TIFFClose(tif);

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

    LLVMFuzzerTestOneInput_220(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
