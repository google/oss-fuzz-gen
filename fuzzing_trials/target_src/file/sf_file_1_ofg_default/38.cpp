#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <magic.h>
#include <string.h>

extern "C" {
    // Function signature to be fuzzed
    const char * magic_descriptor(struct magic_set *, int);
}

extern "C" int LLVMFuzzerTestOneInput_38(const uint8_t *data, size_t size) {
    // Initialize variables
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0;
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0;
    }

    // Ensure we have a valid file descriptor
    int fd = -1;
    if (size > 0) {
        // Create a temporary file to obtain a valid file descriptor
        char tmpl[] = "/tmp/fuzzfileXXXXXX";
        fd = mkstemp(tmpl);
        if (fd == -1) {
            magic_close(magic);
            return 0;
        }

        // Write the data to the temporary file
        if (write(fd, data, size) != (ssize_t)size) {
            close(fd);
            magic_close(magic);
            return 0;
        }

        // Rewind the file descriptor to the beginning
        lseek(fd, 0, SEEK_SET);

        // Call the function-under-test
        const char *result = magic_descriptor(magic, fd);

        // Use the result in some way to avoid compiler optimizations
        if (result != NULL) {
            printf("%s\n", result);
        } else {
            // Handle the case where result is NULL to increase coverage
            fprintf(stderr, "magic_descriptor returned NULL\n");
        }

        // Close the file descriptor and clean up
        close(fd);

        // Remove the temporary file to avoid clutter
        unlink(tmpl);
    }

    magic_close(magic);
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

    LLVMFuzzerTestOneInput_38(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
