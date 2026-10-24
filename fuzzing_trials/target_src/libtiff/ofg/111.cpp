extern "C" {
    #include <tiffio.h>
    #include <unistd.h>  // For mkstemp, write, close
    #include <sys/types.h> // For ssize_t
    #include <stdio.h>  // For remove
    #include <fcntl.h>  // For open flags
    #include <stdlib.h> // For mkstemp
}

extern "C" int LLVMFuzzerTestOneInput_111(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Create a temporary file to write the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return 0;
    }

    // Close the file descriptor
    close(fd);

    // Open the TIFF file using the temporary file name
    TIFF* tiff = TIFFOpen(tmpl, "r");
    if (tiff != NULL) {
        // Call the function-under-test
        int result = TIFFIsTiled(tiff);

        // Close the TIFF file
        TIFFClose(tiff);
    }

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

    LLVMFuzzerTestOneInput_111(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
