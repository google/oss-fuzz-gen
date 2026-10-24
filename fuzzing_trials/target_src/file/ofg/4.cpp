#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <magic.h>

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    struct magic_set *magic = nullptr;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = -1;

    // Ensure the data size is reasonable for a file path
    if (size == 0 || size > 255) {
        return 0;
    }

    // Create a temporary file
    fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the file
    if (write(fd, data, size) != static_cast<ssize_t>(size)) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Close the file descriptor
    close(fd);

    // Initialize the magic library
    magic = magic_open(MAGIC_NONE);
    if (magic == nullptr) {
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test with the temporary file path
    magic_load(magic, tmpl);

    // Clean up
    magic_close(magic);
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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
