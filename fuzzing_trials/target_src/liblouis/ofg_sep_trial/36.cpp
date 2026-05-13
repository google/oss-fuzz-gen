extern "C" {
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <stdint.h> // Include for uint8_t type

    // Function signature provided
    void lou_logPrint(const char *message, void *userData);
}

// Fuzzer entry point
extern "C" int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    // Ensure the data size is non-zero to create a non-empty string
    if (size == 0) return 0;

    // Allocate memory for the message and ensure it's null-terminated
    char *message = (char *)malloc(size + 1);
    if (message == NULL) return 0; // Check for allocation failure

    memcpy(message, data, size);
    message[size] = '\0'; // Null-terminate the string

    // Dummy user data, as the function signature requires a void pointer
    int dummyUserData = 42;
    void *userData = &dummyUserData;

    // Call the function under test
    lou_logPrint(message, userData);

    // Free the allocated memory
    free(message);

    return 0;
}