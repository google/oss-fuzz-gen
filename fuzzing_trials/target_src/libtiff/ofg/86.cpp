#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>  // Include for close, write, and mkstemp
#include <stdlib.h>  // Include for remove

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_86(const uint8_t *data, size_t size) {
    // Create a temporary file to simulate a TIFF file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // If file creation fails, exit
    }

    // Write the fuzzing data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return 0; // If writing fails, exit
    }

    // Close the file descriptor
    close(fd);

    // Open the TIFF file
    TIFF *tiff = TIFFOpen(tmpl, "rm");
    if (tiff == NULL) {
        // If TIFFOpen fails, remove the temporary file and exit
        remove(tmpl);
        return 0;
    }

    // Call the function-under-test
    tdir_t currentDir = TIFFCurrentDirectory(tiff);

    // Cleanup
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

    LLVMFuzzerTestOneInput_86(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
