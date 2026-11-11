#include <stdint.h>
#include <unistd.h>   // Include for mkstemp, write, close
#include <stdlib.h>   // Include for remove
#include <iostream>   // Include for std::cout
#include <cstring>    // Include for memcpy, strlen

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_126(const uint8_t *data, size_t size) {
    if (size < sizeof(uint32_t) + 8) { // Ensure there's enough data for a minimal TIFF header
        return 0;
    }

    // Create a temporary TIFF file
    char tmpl[] = "/tmp/fuzzfileXXXXXX.tiff";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    ssize_t written = write(fd, data, size);
    close(fd);

    // Ensure that the write was successful and the file is not empty
    if (written != size || written == 0) {
        remove(tmpl);
        return 0;
    }

    // Open the TIFF file
    TIFF *tiff = TIFFOpen(tmpl, "r");
    if (tiff == nullptr) {
        remove(tmpl);
        return 0;
    }

    // Extract a uint32_t from the data
    uint32_t tag = *(const uint32_t *)data;

    // Call the function-under-test
    // Attempt to retrieve a field from the TIFF file
    char *fieldValue = nullptr;
    if (TIFFGetField(tiff, tag, &fieldValue)) {
        if (fieldValue && strlen(fieldValue) > 0) { // Ensure the field value is not empty
            // Process the field value in some way
            std::cout << "Field value: " << fieldValue << std::endl;
            TIFFUnsetField(tiff, tag);
        }
    } else {
        // Try to set a field to ensure we are testing more functionality
        const char *sampleValue = "SampleValue";
        TIFFSetField(tiff, tag, sampleValue);
    }

    // Close the TIFF file
    TIFFClose(tiff);

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

    LLVMFuzzerTestOneInput_126(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
