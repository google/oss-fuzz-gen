#include <cstddef>
#include <cstdint>
#include <curl/curl.h>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_83(const uint8_t *data, size_t size) {
    struct curl_httppost *formpost = NULL;
    struct curl_httppost *lastptr = NULL;
    CURLFORMcode result;

    // Ensure the data is not NULL and has a minimum length
    if (size < 2) { // Need at least two bytes to proceed
        return 0;
    }

    // Use the input data to influence the form addition
    // Here, we use the first byte to determine the form option
    int option = data[0] % 3; // Simple modulo to choose an option

    // Use the second byte to determine the length of the content
    size_t content_length = data[1] % (size - 1); // Ensure it does not exceed the input size

    // Ensure content_length is not zero and does not exceed available data
    if (content_length == 0 || content_length > size - 2) {
        content_length = size - 2; // Use all available data if the modulo results in zero
    }

    // Prepare content based on the input data
    const char *content = reinterpret_cast<const char *>(data + 2);

    switch (option) {
        case 0:
            result = curl_formadd(&formpost, &lastptr,
                                  CURLFORM_COPYNAME, "name",
                                  CURLFORM_COPYCONTENTS, content,
                                  CURLFORM_CONTENTSLENGTH, content_length,
                                  CURLFORM_END);
            break;
        case 1:
            result = curl_formadd(&formpost, &lastptr,
                                  CURLFORM_COPYNAME, "anothername",
                                  CURLFORM_COPYCONTENTS, content,
                                  CURLFORM_CONTENTSLENGTH, content_length,
                                  CURLFORM_END);
            break;
        case 2:
            result = curl_formadd(&formpost, &lastptr,
                                  CURLFORM_COPYNAME, "yetanothername",
                                  CURLFORM_COPYCONTENTS, content,
                                  CURLFORM_CONTENTSLENGTH, content_length,
                                  CURLFORM_END);
            break;
        default:
            result = CURL_FORMADD_OK;
            break;
    }

    // Clean up the form post chain
    if (formpost) {
        curl_formfree(formpost);
    }

    return 0;
}