#include <cstdint>
#include <cstdio>
#include <unistd.h>  // For close() and mkstemp()
#include <cstdlib>   // For mkstemp()

// Ensure that the TIFF library functions are correctly linked with C++ code
extern "C" {
    #include <tiffio.h>
}

// Define the fuzzer test function
extern "C" int LLVMFuzzerTestOneInput_186(const uint8_t *data, size_t size) {
    // Create a temporary file to simulate a TIFF file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // Exit if the temporary file cannot be created
    }

    // Write the fuzz data to the temporary file
    FILE *file = fdopen(fd, "wb");
    if (file == nullptr) {
        close(fd);
        return 0; // Exit if the file cannot be opened
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the TIFF file using the TIFF library
    TIFF *tiff = TIFFOpen(tmpl, "r");
    if (tiff == nullptr) {
        remove(tmpl); // Clean up the temporary file
        return 0; // Exit if the TIFF file cannot be opened
    }

    // Call the function-under-test
    thandle_t handle = TIFFClientdata(tiff);

    // Clean up
    TIFFClose(tiff);
    remove(tmpl); // Remove the temporary file

    return 0; // Return success
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

    LLVMFuzzerTestOneInput_186(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
