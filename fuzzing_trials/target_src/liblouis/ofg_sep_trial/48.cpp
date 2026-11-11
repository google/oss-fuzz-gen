#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" {
    // Forward declaration of the function-under-test
    void lou_indexTables(const char **);
}

extern "C" int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size) {
    // Allocate memory for the input strings
    const char *inputStrings[3];

    // Ensure we have enough data to work with
    if (size < 3) {
        return 0;
    }

    // Split the input data into three parts for the input strings
    size_t partSize = size / 3;
    char *str1 = new char[partSize + 1];
    char *str2 = new char[partSize + 1];
    char *str3 = new char[partSize + 1];

    // Copy the data into the strings and null-terminate them
    std::memcpy(str1, data, partSize);
    str1[partSize] = '\0';

    std::memcpy(str2, data + partSize, partSize);
    str2[partSize] = '\0';

    std::memcpy(str3, data + 2 * partSize, partSize);
    str3[partSize] = '\0';

    // Initialize the input array
    inputStrings[0] = str1;
    inputStrings[1] = str2;
    inputStrings[2] = str3;

    // Call the function-under-test
    lou_indexTables(inputStrings);

    // Clean up allocated memory
    delete[] str1;
    delete[] str2;
    delete[] str3;

    return 0;
}