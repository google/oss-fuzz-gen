#include <sys/stat.h>
#include <string.h>
#include "cstdint"
#include "cstdlib"
#include "cstring"
#include <unistd.h>  // Include for close() and write()
#include "tiffio.h"

extern "C" int LLVMFuzzerTestOneInput_46(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for extracting tmsize_t value
    if (size < sizeof(tmsize_t)) {
        return 0;
    }

    // Initialize TIFFOpenOptions
    TIFFOpenOptions *options = TIFFOpenOptionsAlloc();
    if (options == NULL) {
        return 0;
    }

    // Extract tmsize_t value from the input data
    tmsize_t maxSingleMemAlloc = *reinterpret_cast<const tmsize_t*>(data);

    // Call the function-under-test
    TIFFOpenOptionsSetMaxSingleMemAlloc(options, maxSingleMemAlloc);

    // Attempt to open a TIFF stream from the input data to increase code coverage
    // Creating a temporary memory stream from the data
    char tempFileName[] = "/tmp/fuzz_tiff_XXXXXX";
    int fd = mkstemp(tempFileName);
    if (fd == -1) {
        TIFFOpenOptionsFree(options);
        return 0;
    }

    // Write the input data to the temporary file
    write(fd, data, size);
    close(fd);

    // Open the TIFF file using the options
    TIFF *tif = TIFFOpen(tempFileName, "r");
    if (tif != NULL) {
        // Perform some operations to increase coverage
        TIFFReadDirectory(tif);
        TIFFClose(tif);
    }

    // Clean up
    TIFFOpenOptionsFree(options);
    remove(tempFileName);

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

    LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
