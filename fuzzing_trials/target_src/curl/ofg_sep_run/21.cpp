#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>

extern "C" {
    #include <curl/curl.h>
}

extern "C" int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated to be used as a C-string
    char *env_var_name = (char *)malloc(size + 1);
    if (env_var_name == NULL) {
        return 0;
    }
    memcpy(env_var_name, data, size);
    env_var_name[size] = '\0';

    // Call the function-under-test
    char *result = curl_getenv(env_var_name);

    // If curl_getenv returns a non-NULL result, free it
    if (result != NULL) {
        free(result);
    }

    // Free the allocated memory for env_var_name
    free(env_var_name);

    return 0;
}