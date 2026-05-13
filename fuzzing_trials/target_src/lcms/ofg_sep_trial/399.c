#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_399(const uint8_t *data, size_t size) {
    cmsContext context;
    cmsHANDLE handle;
    char *filename;
    FILE *file;

    // Create a temporary file to write the input data
    filename = tmpnam(NULL);
    if (filename == NULL) {
        return 0;
    }

    file = fopen(filename, "wb");
    if (file == NULL) {
        return 0;
    }

    fwrite(data, 1, size, file);
    fclose(file);

    // Initialize the context
    context = cmsCreateContext(NULL, NULL);

    // Call the function under test
    handle = cmsIT8LoadFromFile(context, filename);

    // Clean up
    if (handle != NULL) {
        cmsIT8Free(handle);
    }
    cmsDeleteContext(context);

    // Remove the temporary file
    remove(filename);

    return 0;
}