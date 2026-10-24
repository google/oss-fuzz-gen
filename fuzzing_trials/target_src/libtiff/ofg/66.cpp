#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_66(const uint8_t *data, size_t size) {
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

    // Rewind the file descriptor to the beginning
    lseek(fd, 0, SEEK_SET);

    // Define options for opening the TIFF file
    TIFFOpenOptions *options = TIFFOpenOptionsAlloc();
    if (options == nullptr) {
        close(fd);
        unlink(tmpl);
        return 0;
    }
    
    // Initialize options if the function exists in the library
    // Commenting out the line that caused the error because the function might not exist
    // TIFFOpenOptionsInit(options);

    // Open the TIFF file using the file descriptor
    TIFF *tiff = TIFFFdOpenExt(fd, tmpl, "r", options);
    if (tiff != nullptr) {
        // Close the TIFF file if it was successfully opened
        TIFFClose(tiff);
    }

    // Clean up
    TIFFOpenOptionsFree(options);
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

    LLVMFuzzerTestOneInput_66(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
