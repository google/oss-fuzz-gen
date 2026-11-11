#include <cstdint>
#include <cstddef>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <cstdlib> // Include for mkstemp

// Assume plist_is_binary is defined in an external C library
extern "C" {
    int plist_is_binary(const char *filename, uint32_t options);
}

extern "C" int LLVMFuzzerTestOneInput_173(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0; // Exit early if there's no data to process
    }

    // Create a temporary file to write the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // If file creation fails, exit early
    }

    // Write the fuzz data to the temporary file
    ssize_t written = write(fd, data, size);
    close(fd);

    if (written != size) {
        unlink(tmpl);
        return 0; // If write fails, exit early
    }

    // Set a non-zero options value for testing
    uint32_t options = 1;

    // Call the function-under-test with the temporary file name
    plist_is_binary(tmpl, options);

    // Clean up the temporary file
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

    LLVMFuzzerTestOneInput_173(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
