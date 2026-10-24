#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <magic.h>
#include <unistd.h> // Include for write, close, and unlink
#include <fcntl.h>  // Include for mkstemp

extern "C" {
    // Include necessary C headers and functions here.
    const char * magic_descriptor(struct magic_set *, int);
}

extern "C" int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Initialize a magic_set structure
    struct magic_set *ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        fprintf(stderr, "Failed to initialize magic_set\n");
        return 0; // Unable to allocate magic_set, exit early
    }

    // Load default magic database
    if (magic_load(ms, NULL) != 0) {
        fprintf(stderr, "Failed to load magic database: %s\n", magic_error(ms));
        magic_close(ms);
        return 0; // Unable to load magic database, exit early
    }

    // Ensure the size is sufficient to create a file descriptor
    if (size == 0) {
        magic_close(ms);
        return 0;
    }

    // Create a temporary file to obtain a valid file descriptor
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        magic_close(ms);
        return 0; // Unable to create a temporary file, exit early
    }

    // Write the input data to the temporary file
    if (write(fd, data, size) == -1) {
        perror("write");
        close(fd);
        unlink(tmpl); // Ensure the temporary file is removed
        magic_close(ms);
        return 0; // Unable to write data, exit early
    }

    // Reset the file offset to the beginning of the file
    if (lseek(fd, 0, SEEK_SET) == -1) {
        perror("lseek");
        close(fd);
        unlink(tmpl); // Ensure the temporary file is removed
        magic_close(ms);
        return 0; // Unable to reset file offset, exit early
    }

    // Use the file descriptor with the function-under-test
    const char *result = magic_descriptor(ms, fd);

    // Check if the result is not NULL to ensure the function is being exercised
    if (result != NULL) {
        printf("Magic descriptor result: %s\n", result);
    } else {
        // If the result is NULL, print a message to aid in debugging
        fprintf(stderr, "Magic descriptor returned NULL: %s\n", magic_error(ms));
    }

    // Clean up
    close(fd);
    unlink(tmpl); // Remove the temporary file
    magic_close(ms);

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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
