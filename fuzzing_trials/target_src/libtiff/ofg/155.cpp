extern "C" {
    #include <tiffio.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <stdlib.h>  // Include for mkstemp
}

extern "C" int LLVMFuzzerTestOneInput_155(const uint8_t *data, size_t size) {
    // Create a temporary file
    char filename[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(filename);
    if (fd == -1) {
        return 0; // Return if file creation fails
    }

    // Write data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(filename);
        return 0; // Return if writing fails
    }

    // Close the file descriptor
    close(fd);

    // Open the file with TIFF library
    TIFF *tif = TIFFOpen(filename, "r");
    if (tif == nullptr) {
        unlink(filename);
        return 0; // Return if TIFF structure is not initialized
    }

    // Call the function-under-test
    int result = TIFFCreateDirectory(tif);

    // Clean up
    TIFFClose(tif);
    unlink(filename);

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

    LLVMFuzzerTestOneInput_155(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
