#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

// Function signature to be fuzzed
long cmsfilelength(FILE *file);

// Fuzzing harness
int LLVMFuzzerTestOneInput_428(const uint8_t *data, size_t size) {
    // Create a temporary file to write the fuzzing data
    FILE *tempFile = tmpfile();
    if (tempFile == NULL) {
        return 0;
    }

    // Write the fuzzing data to the temporary file
    fwrite(data, 1, size, tempFile);

    // Reset the file pointer to the beginning of the file
    rewind(tempFile);

    // Call the function-under-test
    long length = cmsfilelength(tempFile);

    // Close the temporary file
    fclose(tempFile);

    return 0;
}