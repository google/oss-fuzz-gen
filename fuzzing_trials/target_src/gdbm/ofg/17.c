#include <stdio.h>
#include <stdint.h>

// Function-under-test declaration
void variable_print_all(FILE *);

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    // Create a temporary file to pass to the function-under-test
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }

    // Write the fuzzing data to the temporary file
    if (write(fd, data, size) != size) {
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