#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

// Assuming rr_t is a structure defined somewhere in the codebase
typedef struct {
    int type;
    char name[256];
    // other fields...
} rr_t;

// Function prototype for the function-under-test
void print_rr(FILE *file, rr_t *record);

int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    // Ensure there is enough data to fill the rr_t structure
    if (size < sizeof(rr_t)) {
        return 0;
    }

    // Create a temporary file to pass as FILE* to print_rr
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp failed");
        return 0;
    }
    FILE *file = fdopen(fd, "w+");
    if (file == NULL) {
        perror("fdopen failed");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Initialize an rr_t structure with data from the fuzzer
    rr_t record;
    memcpy(&record, data, sizeof(rr_t));

    // Ensure null-termination of the name field to prevent buffer overflow
    record.name[sizeof(record.name) - 1] = '\0';

    // Validate and sanitize the 'type' field to avoid invalid operations
    if (record.type < 0 || record.type > 100) {  // Assuming valid type range is 0-100
        fclose(file);
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    print_rr(file, &record);

    // Rewind the file to read its content if needed
    fseek(file, 0, SEEK_SET);

    // Read back the content to ensure the file operations are working as expected
    char buffer[512];
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        // Process the output if needed; for now, just print it
        printf("%s", buffer);
    }

    // Clean up
    fclose(file);
    unlink(tmpl);

    return 0;
}