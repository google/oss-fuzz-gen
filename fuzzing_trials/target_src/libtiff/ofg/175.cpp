#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // Include for write and close functions

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_175(const uint8_t *data, size_t size) {
    TIFF *tif = nullptr;
    tdir_t dirnum = 0;

    // Create a temporary file to hold the TIFF data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return 0;
    }
    close(fd);

    // Open the TIFF file
    tif = TIFFOpen(tmpl, "r+");
    if (tif == nullptr) {
        remove(tmpl);
        return 0;
    }

    // Call the function-under-test
    TIFFUnlinkDirectory(tif, dirnum);

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

    LLVMFuzzerTestOneInput_175(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
