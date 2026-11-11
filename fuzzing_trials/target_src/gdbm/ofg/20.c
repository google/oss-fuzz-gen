#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function-under-test
void terror(const char *message, void *data);

// Fuzzing harness
int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a non-empty string
    if (size < 1) {
        return 0;
    }

    // Allocate memory for the message string, ensuring it's null-terminated
    char *message = (char *)malloc(size + 1);
    if (!message) {
        return 0;
    }
    memcpy(message, data, size);
    message[size] = '\0';  // Null-terminate the string

    // Create a dummy non-NULL pointer for the second parameter
    int dummyData = 42;
    void *dataPtr = &dummyData;

    // Call the function-under-test
    // Ensure the inputs are valid and handle any potential exceptions or errors
    if (message && dataPtr) {
        // Since C doesn't have a built-in try-catch, we rely on careful input validation
        // Call the function and check for any abnormal behavior
        // Ensure the message is a valid string and dataPtr is a valid pointer
        // Add additional checks to ensure message is a valid UTF-8 string if required by `terror`
        for (size_t i = 0; i < size; i++) {
            if (message[i] == '\0') {
                // If there are null characters in the middle, consider it invalid
                free(message);
                return 0;
            }
        }
        
        terror(message, dataPtr);
    }

    // Clean up
    free(message);

    return 0;
}