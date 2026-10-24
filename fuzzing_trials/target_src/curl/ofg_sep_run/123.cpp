#include <cstddef>
#include <cstring>
#include <string>

extern "C" {
    #include <curl/curl.h>
}

extern "C" int LLVMFuzzerTestOneInput_123(const uint8_t *data, size_t size) {
    // Ensure there's enough data to create two strings
    if (size < 2) {
        return 0;
    }

    // Split the input data into two parts for the two strings
    size_t mid = size / 2;
    const char *str1 = reinterpret_cast<const char*>(data);
    const char *str2 = reinterpret_cast<const char*>(data + mid);

    // Ensure null-termination of the strings
    std::string s1(str1, mid);
    std::string s2(str2, size - mid);

    // Call the function-under-test
    int result = curl_strequal(s1.c_str(), s2.c_str());

    // Use the result to avoid any compiler optimizations
    volatile int avoid_optimization = result;
    (void)avoid_optimization;

    return 0;
}