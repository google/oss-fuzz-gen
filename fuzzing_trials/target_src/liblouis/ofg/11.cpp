#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <unistd.h> // Include for the 'close' function

extern "C" {
    // Include the function-under-test
    int lou_readCharFromFile(const char *, int *);
}

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient
    if (size == 0) {
        return 0;
    }

    // Create a temporary file to store the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // If file creation fails, exit early
    }

    // Write the fuzz data to the temporary file
    FILE *file = fdopen(fd, "wb");
    if (file == nullptr) {
        close(fd);
        return 0;
    }

    fwrite(data, 1, size, file);
    fclose(file);

    // Prepare the second parameter for the function
    int resultValue = 0;

    // Call the function-under-test
    lou_readCharFromFile(tmpl, &resultValue);

    // Clean up: remove the temporary file
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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
