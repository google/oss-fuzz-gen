#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>

extern "C" {
    #include "magic.h"
}

// Function-under-test
extern "C" const char * magic_descriptor(struct magic_set *, int);

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a temporary file
    if (size < 1) {
        return 0;
    }

    // Create a temporary file to use its file descriptor
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp failed");
        return 0;
    }

    // Write data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        perror("write failed");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Reset file offset to the beginning
    if (lseek(fd, 0, SEEK_SET) == -1) {
        perror("lseek failed");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Initialize the magic_set structure
    struct magic_set *ms = magic_open(MAGIC_NONE);
    if (ms == nullptr) {
        fprintf(stderr, "magic_open failed\n");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Load the default magic database
    if (magic_load(ms, nullptr) != 0) {
        fprintf(stderr, "magic_load failed: %s\n", magic_error(ms));
        magic_close(ms);
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    const char *result = magic_descriptor(ms, fd);

    // Check the result to ensure it's not null
    if (result != nullptr) {
        // Print the result to increase coverage
        printf("Magic descriptor result: %s\n", result);
    } else {
        // Print a message indicating a null result
        printf("Magic descriptor returned null.\n");
    }

    // Cleanup
    magic_close(ms);
    close(fd);
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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
