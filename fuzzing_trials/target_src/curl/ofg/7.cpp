#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib> // Include for malloc and free
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated to safely pass as a C string
    char *input = static_cast<char*>(malloc(size + 1));
    if (input == nullptr) {
        return 0; // If memory allocation fails, exit early
    }

    memcpy(input, data, size);
    input[size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    char *result = curl_unescape(input, static_cast<int>(size));

    // Free the result if it is not NULL
    if (result != nullptr) {
        curl_free(result);
    }

    // Free the allocated input
    free(input);

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
