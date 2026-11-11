#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    // Callback function for curl_formget
    static size_t formget_callback(void *arg, const char *buf, size_t len) {
        // Simply return the length of the buffer to simulate processing
        return len;
    }

    int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
        // Initialize curl_httppost structure
        struct curl_httppost *formpost = NULL;
        struct curl_httppost *lastptr = NULL;

        // Ensure that size is non-zero to avoid unnecessary operations
        if (size == 0) {
            return 0;
        }

        // Use the input data to create a form
        // Note: This is a simple simulation, in a real scenario you should parse the data properly
        char *field_name = (char *)malloc(size + 1);
        char *field_value = (char *)malloc(size + 1);

        if (field_name == NULL || field_value == NULL) {
            free(field_name);
            free(field_value);
            return 0;
        }

        // Copy data into field_name and field_value
        memcpy(field_name, data, size);
        field_name[size] = '\0';  // Null-terminate the string
        memcpy(field_value, data, size);
        field_value[size] = '\0';  // Null-terminate the string

        // Add a form section
        curl_formadd(&formpost, &lastptr,
                     CURLFORM_COPYNAME, field_name,
                     CURLFORM_COPYCONTENTS, field_value,
                     CURLFORM_END);

        // Call the function-under-test
        curl_formget(formpost, NULL, formget_callback);

        // Clean up
        curl_formfree(formpost);
        free(field_name);
        free(field_value);

        return 0;
    }
}