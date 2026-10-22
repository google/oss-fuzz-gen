#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <magic.h>
#include <cstring> // Include the C++ header for strlen
#include <unistd.h> // Include for open, close, and other POSIX functions
#include <fcntl.h> // Include for file control options
#include <sys/types.h>
#include <sys/stat.h>

extern "C" {
    // Function signature for the function-under-test
    const char * magic_descriptor(struct magic_set *, int);
}

extern "C" int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    // Initialize a magic_set structure
    struct magic_set *mset = magic_open(MAGIC_NONE);
    if (mset == NULL) {
        return 0; // If magic_open fails, return early
    }

    // Load the default magic database
    if (magic_load(mset, NULL) != 0) {
        magic_close(mset);
        return 0; // If magic_load fails, return early
    }

    // Create a temporary file to simulate a valid file descriptor
    char temp_filename[] = "/tmp/fuzzfileXXXXXX";
    int temp_fd = mkstemp(temp_filename);
    if (temp_fd == -1) {
        magic_close(mset);
        return 0; // If mkstemp fails, return early
    }

    // Write the fuzz data to the temporary file
    if (write(temp_fd, data, size) != static_cast<ssize_t>(size)) {
        close(temp_fd);
        unlink(temp_filename);
        magic_close(mset);
        return 0; // If write fails, return early
    }

    // Rewind the file descriptor to the beginning
    if (lseek(temp_fd, 0, SEEK_SET) == -1) {
        close(temp_fd);
        unlink(temp_filename);
        magic_close(mset);
        return 0; // If lseek fails, return early
    }

    // Call the function-under-test with a valid file descriptor
    const char *result = magic_descriptor(mset, temp_fd);

    // Use the result in some way to prevent optimization out
    if (result != NULL) {
        // For example, print the result or perform some operation
        // Here we just check the length of the result
        size_t len = std::strlen(result); // Use std::strlen from <cstring>
        // Additional operation to ensure the result is used
        volatile size_t dummy = len; // Prevent optimization out
    }

    // Clean up
    close(temp_fd); // Close the temporary file descriptor
    unlink(temp_filename); // Remove the temporary file
    magic_close(mset);

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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
