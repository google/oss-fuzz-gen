#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

// Function-under-test declaration
void variable_print_all(FILE *);

int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    // Create a temporary file to write the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }

    // Write fuzz data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        perror("write");
        close(fd);
        return 0;
    }

    // Rewind the file descriptor to the beginning
    if (lseek(fd, 0, SEEK_SET) == -1) {
        perror("lseek");
        close(fd);
        return 0;
    }

    // Open the file as a FILE* stream
    FILE *file = fdopen(fd, "r");
    if (!file) {
        perror("fdopen");
        close(fd);
        return 0;
    }

    // Call the function-under-test
    variable_print_all(file);

    // Clean up
    fclose(file);
    unlink(tmpl);

    return 0;
}