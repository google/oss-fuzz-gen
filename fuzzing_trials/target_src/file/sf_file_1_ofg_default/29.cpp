#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <magic.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

extern "C" {
    // Include the function-under-test
    const char * magic_descriptor(struct magic_set *, int);
}

extern "C" int LLVMFuzzerTestOneInput_29(const uint8_t *data, size_t size) {
    // Initialize parameters for magic_descriptor
    struct magic_set *ms;
    int fd;
    char filename[] = "/tmp/fuzzfileXXXXXX";

    // Create a magic set
    ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        return 0;
    }

    // Load the default magic database
    if (magic_load(ms, NULL) != 0) {
        magic_close(ms);
        return 0;
    }

    // Ensure size is large enough to create a valid temporary file
    if (size < 1) {
        magic_close(ms);
        return 0;
    }

    // Create a temporary file
    fd = mkstemp(filename);
    if (fd == -1) {
        magic_close(ms);
        return 0;
    }

    // Write data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(filename);
        magic_close(ms);
        return 0;
    }

    // Reset file offset to the beginning
    if (lseek(fd, 0, SEEK_SET) == -1) {
        close(fd);
        unlink(filename);
        magic_close(ms);
        return 0;
    }

    // Call the function-under-test
    const char *result = magic_descriptor(ms, fd);

    // Check if the result is not NULL and handle it
    if (result != NULL) {
        // Print the result (for debugging purposes)
        printf("Magic Descriptor: %s\n", result);
    } else {
        // Print an error message if result is NULL
        fprintf(stderr, "Error: magic_descriptor returned NULL\n");
    }

    // Clean up
    close(fd);
    unlink(filename);
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

    LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
