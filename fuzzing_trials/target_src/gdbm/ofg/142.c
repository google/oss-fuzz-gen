#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h> // Include for file control options

// Assuming gdbm_import_from_file is a custom function
// Provide a mock implementation for demonstration purposes
int gdbm_import_from_file_142(GDBM_FILE dbf, FILE *file_stream, int flags) {
    // Mock implementation: read from file and perform some operations
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), file_stream)) {
        // Simulate processing the file content
    }
    return 0; // Return success
}

int LLVMFuzzerTestOneInput_142(const uint8_t *data, size_t size) {
    // Create a temporary file
    char tmp_filename[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmp_filename);
    if (fd == -1) {
        perror("mkstemp");
        exit(1);
    }

    // Write the fuzzing data to the temporary file
    if (write(fd, data, size) < size) {
        close(fd);
        perror("write");
        exit(1);
    }

    // Rewind the file descriptor to the beginning
    if (lseek(fd, 0, SEEK_SET) != 0) {
        close(fd);
        perror("lseek");
        exit(1);
    }

    // Open the file descriptor as a FILE* stream
    FILE *file_stream = fdopen(fd, "r");
    if (!file_stream) {
        close(fd);
        perror("fdopen");
        exit(1);
    }

    // Open a GDBM database with the GDBM_NEWDB flag
    GDBM_FILE dbf = gdbm_open(tmp_filename, 512, GDBM_NEWDB, 0644, NULL);
    if (!dbf) {
        fclose(file_stream);
        perror("gdbm_open");
        exit(1);
    }

    // Call the function-under-test
    int result = gdbm_import_from_file_142(dbf, file_stream, 0);

    // Clean up
    gdbm_close(dbf);
    fclose(file_stream);
    unlink(tmp_filename); // Remove the temporary file

    return result;
}