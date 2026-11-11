#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h> // Include for open(), close(), and O_RDWR

// Declare the function-under-test
int yylex();

// Fuzzing harness
int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
    // Create a temporary file to store the fuzzing input
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }

    // Write the fuzzing input data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        perror("write");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Reset the file descriptor offset to the beginning of the file
    if (lseek(fd, 0, SEEK_SET) == -1) {
        perror("lseek");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Redirect standard input to the temporary file
    FILE *file = fdopen(fd, "r");
    if (!file) {
        perror("fdopen");
        close(fd);
        unlink(tmpl);
        return 0;
    }
    // Save the original stdin file descriptor
    int original_stdin_fd = dup(STDIN_FILENO);
    if (original_stdin_fd == -1) {
        perror("dup");
        fclose(file);
        unlink(tmpl);
        return 0;
    }

    // Redirect stdin to the file
    if (dup2(fd, STDIN_FILENO) == -1) {
        perror("dup2");
        fclose(file);
        close(original_stdin_fd);
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    yylex();

    // Restore the original stdin
    dup2(original_stdin_fd, STDIN_FILENO);
    close(original_stdin_fd);

    // Clean up
    fclose(file);
    unlink(tmpl);

    return 0;
}