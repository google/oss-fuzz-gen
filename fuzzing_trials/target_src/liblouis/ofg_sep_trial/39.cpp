#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>

extern "C" {
    // Include the actual header for the function-under-test
    #include "/src/liblouis/liblouis/liblouis.h"
}

// Function signature to fuzz
extern "C" char * lou_getTableInfo(const char *, const char *);

// Fuzzing harness
extern "C" int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to create two non-null strings
    if (size < 2) {
        return 0;
    }

    // Calculate lengths for the two strings
    size_t len1 = size / 2;
    size_t len2 = size - len1;

    // Allocate memory for the two strings, ensuring they are null-terminated
    char *tableName = (char *)malloc(len1 + 1);
    char *infoType = (char *)malloc(len2 + 1);

    if (tableName == NULL || infoType == NULL) {
        free(tableName);
        free(infoType);
        return 0;
    }

    // Copy data into the strings and null-terminate them
    memcpy(tableName, data, len1);
    tableName[len1] = '\0';

    memcpy(infoType, data + len1, len2);
    infoType[len2] = '\0';

    // Call the function-under-test
    char *result = lou_getTableInfo(tableName, infoType);

    // Free the allocated memory
    free(tableName);
    free(infoType);

    // If the function returns a dynamically allocated string, free it
    if (result != NULL) {
        free(result);
    }

    return 0;
}