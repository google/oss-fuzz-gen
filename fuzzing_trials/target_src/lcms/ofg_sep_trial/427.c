#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

extern long cmsfilelength(FILE *);

int LLVMFuzzerTestOneInput_427(const uint8_t *data, size_t size) {
    // Create a temporary file to write the input data
    FILE *temp_file = tmpfile();
    if (temp_file == NULL) {
        return 0;
    }

    // Write the input data to the temporary file
    size_t written = fwrite(data, 1, size, temp_file);
    if (written != size) {
        fclose(temp_file);
        return 0;
    }

    // Rewind the file to the beginning for reading
    rewind(temp_file);

    // Call the function-under-test
    long length = cmsfilelength(temp_file);

    // Close the temporary file
    fclose(temp_file);

    return 0;
}