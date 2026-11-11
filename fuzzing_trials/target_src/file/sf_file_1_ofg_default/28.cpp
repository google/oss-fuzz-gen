#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h> // Include for mkstemp
#include <string.h> // Include for memcpy

extern "C" {
    #include <magic.h> // Include this within extern "C" to ensure C linkage

    // Function signature from the project-under-test
    const char *magic_descriptor(struct magic_set *, int);
}

extern "C" int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    // Initialize a magic_set structure
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0; // If magic_open fails, return immediately
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0; // If magic_load fails, return immediately
    }

    // Ensure size is non-zero and within a reasonable range for file descriptors
    if (size == 0 || size > 1024) {
        magic_close(magic);
        return 0;
    }

    // Create a temporary file and write the data to it
    char filename[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(filename);
    if (fd == -1) {
        magic_close(magic);
        return 0;
    }

    // Write the data to the file
    if (write(fd, data, size) != (ssize_t)size) { // Cast size to ssize_t for comparison
        close(fd);
        unlink(filename);
        magic_close(magic);
        return 0;
    }

    // Reset the file descriptor's offset to the beginning
    lseek(fd, 0, SEEK_SET);

    // Call the function-under-test
    const char *result = magic_descriptor(magic, fd);

    // Check result to ensure it is not NULL and has valid content
    if (result != NULL && result[0] != '\0') {
        // The result is valid, indicating the function processed the input
        printf("Magic descriptor result: %s\n", result); // Print result for debugging
    }

    // Clean up
    close(fd);
    unlink(filename);
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

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
