#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>  // For mkstemp, write, and close
#include <fcntl.h>   // For open
#include <sys/types.h> // For ssize_t
#include <stdlib.h>  // For remove

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0; // Ensure there's enough data for a valid TIFF header
    }

    // Create a temporary file to write the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // Failed to create a temporary file
    }

    // Write the fuzz data to the temporary file
    ssize_t written = write(fd, data, size);
    if (written != size) {
        close(fd);
        return 0; // Failed to write all data
    }

    // Close the file descriptor
    close(fd);

    // Open the TIFF file using the temporary filename
    TIFF* tif = TIFFOpen(tmpl, "r");
    if (tif == NULL) {
        // Clean up the temporary file
        remove(tmpl);
        return 0; // Failed to open the TIFF file
    }

    // Call the function-under-test
    tmsize_t scanlineSize = TIFFScanlineSize(tif);

    // Clean up
    TIFFClose(tif);
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

    LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
