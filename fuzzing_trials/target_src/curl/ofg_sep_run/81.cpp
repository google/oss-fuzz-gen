#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

extern "C" {
    void curl_formfree(struct curl_httppost *);
    CURLcode curl_easy_perform(CURL *easy_handle);
    CURL *curl_easy_init(void);
    void curl_easy_cleanup(CURL *easy_handle);
    CURLFORMcode curl_formadd(struct curl_httppost **, struct curl_httppost **, ...);
    CURLcode curl_easy_setopt(CURL *curl, CURLoption option, ...);
}

extern "C" int LLVMFuzzerTestOneInput_81(const uint8_t *data, size_t size) {
    // Initialize curl_httppost structure
    struct curl_httppost *formpost = NULL;
    struct curl_httppost *lastptr = NULL;
    CURL *curl;

    if (size > 0) {
        // Use the input data to create a form entry
        char *fieldName = (char *)malloc(size + 1);
        char *fieldContents = (char *)malloc(size + 1);
        if (fieldName == NULL || fieldContents == NULL) {
            free(fieldName);
            free(fieldContents);
            return 0; // Exit if memory allocation fails
        }
        memcpy(fieldName, data, size);
        fieldName[size] = '\0'; // Null-terminate the string
        memcpy(fieldContents, data, size);
        fieldContents[size] = '\0'; // Null-terminate the string

        // Add a form entry using the input data as the field name and contents
        curl_formadd(&formpost,
                     &lastptr,
                     CURLFORM_COPYNAME, fieldName,
                     CURLFORM_COPYCONTENTS, fieldContents,
                     CURLFORM_END);

        free(fieldName);
        free(fieldContents);
    }

    // Initialize a CURL session
    curl = curl_easy_init();
    if (curl) {
        // Set the formpost data
        curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);

        // Set a URL to perform the request
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com");

        // Perform the request, this will invoke the function under test
        curl_easy_perform(curl);

        // Cleanup the CURL session
        curl_easy_cleanup(curl);
    }

    // Free the form post chain
    curl_formfree(formpost);

    return 0;
}