#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_169(const uint8_t *data, size_t size) {
    // Create a temporary file to write the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // If we can't create a temp file, just return
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);
        return 0; // If we can't write all data, clean up and return
    }

    // Rewind the file descriptor to the beginning
    lseek(fd, 0, SEEK_SET);

    // Open the temporary file as a FILE* stream
    FILE *file = fdopen(fd, "rb");
    if (!file) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Initialize GDBM_FILE
    GDBM_FILE dbf = gdbm_open(tmpl, 512, GDBM_WRCREAT, 0666, NULL);
    if (!dbf) {
        fclose(file);
        unlink(tmpl);
        return 0;
    }

    // Prepare the other parameters
    int replace = 1; // Arbitrary non-zero value
    int flag = 0;    // Arbitrary value
    unsigned long count = 0;

    // Call the function-under-test
    gdbm_load_from_file(dbf, file, replace, flag, &count);

    // Clean up
    gdbm_close(dbf);
    fclose(file);
    unlink(tmpl);

    return 0;
}