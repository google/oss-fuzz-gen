#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include <curl/curl.h>
}

// Fuzzing harness for curl_getenv
extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    // Ensure the input data is null-terminated and non-empty
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the environment variable name and ensure null-termination
    char *env_var = (char *)malloc(size + 1);
    if (env_var == NULL) {
        return 0;
    }

    memcpy(env_var, data, size);
    env_var[size] = '\0';

    // Call the function-under-test
    char *result = curl_getenv(env_var);

    // Free the result if it's not NULL
    if (result != NULL) {
        free(result);
    }

    // Free the allocated environment variable name
    free(env_var);

    return 0;
}