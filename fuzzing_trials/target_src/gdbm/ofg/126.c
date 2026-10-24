#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Assuming the definition of struct locus
struct locus {
    int line;
    int column;
    const char *filename;
};

// Function-under-test
void locus_print(FILE *file, const struct locus *loc);

int LLVMFuzzerTestOneInput_126(const uint8_t *data, size_t size) {
    // Create a temporary file to pass as FILE* parameter
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }

    FILE *file = fdopen(fd, "w+");
    if (!file) {
        perror("fdopen");
        close(fd);
        return 0;
    }

    // Ensure the data is large enough to extract necessary fields
    if (size < sizeof(int) * 2 + 1) {
        fclose(file);
        unlink(tmpl);
        return 0;
    }

    // Initialize struct locus with data from the fuzz input
    struct locus loc;
    loc.line = *((int *)data);
    loc.column = *((int *)(data + sizeof(int)));

    // Ensure filename is null-terminated and within bounds
    size_t filename_length = size - sizeof(int) * 2;
    char *filename_buffer = (char *)malloc(filename_length + 1);
    if (!filename_buffer) {
        fclose(file);
        unlink(tmpl);
        return 0;
    }
    memcpy(filename_buffer, data + sizeof(int) * 2, filename_length);
    filename_buffer[filename_length] = '\0'; // Null-terminate the filename
    loc.filename = filename_buffer;

    // Validate the line and column numbers to prevent potential issues
    if (loc.line < 0 || loc.column < 0) {
        free(filename_buffer);
        fclose(file);
        unlink(tmpl);
        return 0;
    }

    // Ensure the filename is valid
    if (strlen(loc.filename) == 0) {
        free(filename_buffer);
        fclose(file);
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    locus_print(file, &loc);

    // Clean up
    free(filename_buffer);
    fclose(file);
    unlink(tmpl);

    return 0;
}