#include <cstdint>
#include <cstddef>
#include <cstring>
#include <algorithm>
#include <curl/curl.h>

extern "C" {
    #include <curl/curl.h>
}

extern "C" int LLVMFuzzerTestOneInput_82(const uint8_t *data, size_t size) {
    // Declare pointers for curl_httppost structures
    struct curl_httppost *formpost = nullptr;
    struct curl_httppost *lastptr = nullptr;

    // Initialize CURLFORMcode
    CURLFORMcode result;

    // Ensure data is not empty
    if (size == 0) {
        return 0;
    }

    // Use the data as a string for form data
    char *formData = new char[size + 1];
    std::copy(data, data + size, formData);
    formData[size] = '\0';

    // Call the function-under-test
    result = curl_formadd(&formpost, &lastptr,
                          CURLFORM_COPYNAME, "name",
                          CURLFORM_COPYCONTENTS, formData,
                          CURLFORM_END);

    // Clean up
    if (formpost) {
        curl_formfree(formpost);
    }
    delete[] formData;

    return 0;
}