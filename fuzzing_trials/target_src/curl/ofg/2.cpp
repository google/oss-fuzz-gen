#include <cstddef>
#include <cstdint>
#include <curl/curl.h>
#include <cstring>
#include <cstdlib> // For malloc and free

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    CURLU *url;
    CURLUcode result;
    CURLUPart part;
    unsigned int flags;

    // Initialize a CURLU handle
    url = curl_url();
    if (!url) {
        return 0;
    }

    // Ensure that the data is null-terminated to be used as a string
    char *input = (char *)malloc(size + 1);
    if (!input) {
        curl_url_cleanup(url);
        return 0;
    }
    memcpy(input, data, size);
    input[size] = '\0';

    // Use the first byte of data to determine the CURLUPart
    part = static_cast<CURLUPart>(data[0] % (CURLUPART_ZONEID + 1));

    // Use the second byte of data to determine the flags
    if (size > 1) {
        flags = static_cast<unsigned int>(data[1]);
    } else {
        flags = 0; // Default flag if not enough data
    }

    // Call the function-under-test
    result = curl_url_set(url, part, input, flags);

    // Clean up
    free(input);
    curl_url_cleanup(url);

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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
